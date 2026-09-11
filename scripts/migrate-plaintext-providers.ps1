# migrate-plaintext-providers.ps1 - 存量明文 provider 迁移（M2 B-1）
#
# 设计：docs/管理门户-apiTokens-Secret化-M2细化方案.md §3.1。
#
# 目标：把控制台中仍是「明文 apiTokens」形态的 provider 迁移为 broker 托管形态，
# 使 WasmPlugin CR 不再含明文 Key；全过程审计留痕，且可回滚。
#
# 迁移动作（逐 provider）：
#   a. 从控制台读取明文 Key（GET /v1/ai/providers；CR 由该状态派生，故以控制台为权威源）
#   b. 经文件直传写入 broker 凭据（curl --data-binary @file，Key 不进命令行/进程列表，临时文件用后即删）
#   c. 更新控制台 provider：tokens 清空 + openaiCustomUrl → broker 端点
#   d. 追加审计登记（Key 指纹 SHA-256 前 8 位 + 操作人 + 时间 + 原 customUrl + 回滚命令）
#
# 回滚（-Mode rollback）：从 broker 凭据文件读回 Key → 控制台 provider 还原为明文形态
#   （tokens=[key] + customUrl 还原）。**该动作把明文写回 CR，属高敏变更**，须双人审批。
#
# 用法：
#   # 1) 预演（默认，无副作用）：列出待迁移清单与迁移前后差异（Key 仅显示指纹）
#   powershell -ExecutionPolicy Bypass -File scripts\migrate-plaintext-providers.ps1
#   # 2) 执行（需显式确认 + 与服务一致的内部令牌密钥）
#   powershell -ExecutionPolicy Bypass -File scripts\migrate-plaintext-providers.ps1 -Mode apply -Yes `
#       -JwtSecret <ADMIN_SVC_JWT_SECRET> -Operator <工号/姓名>
#   # 3) 回滚单条
#   powershell -ExecutionPolicy Bypass -File scripts\migrate-plaintext-providers.ps1 -Mode rollback -Provider phala -Yes `
#       -JwtSecret <ADMIN_SVC_JWT_SECRET> -Operator <工号/姓名>
#
# 退出码：0 = 成功（含 dry-run）；1 = 存在失败。
#
# 注：本脚本为 UTF-8 with BOM；含中文，勿改为无 BOM 保存（PS 5.1 按 ANSI 解析会坏语法）。

param(
    [ValidateSet('dry-run', 'apply', 'rollback')]
    [string]$Mode = 'dry-run',
    [string]$Provider = '',                                     # 空 = 处理全部匹配项
    [string]$Container = 'higress-chain-control-plane',
    [int]$ConsolePort = 18001,
    [string]$BrokerBase = 'http://127.0.0.1:19095',              # 管理面（凭据端点，受内部令牌保护）
    [string]$BrokerPublicBase = 'http://host.docker.internal:19096', # 生成 provider customUrl 的基址
    [string]$User = 'adminExtSmoke',
    [string]$Pass = 'Adm1n-Smoke-2026',
    [string]$JwtSecret = '',                                     # 与服务一致的 ADMIN_SVC_JWT_SECRET
    [string]$Operator = '',
    [string]$SecretsDir = '',                                    # 凭据目录（回滚读 Key 用）；缺省 deploy/secrets/broker-providers
    [switch]$Yes                                                 # apply/rollback 的显式确认
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $SecretsDir) { $SecretsDir = Join-Path $repoRoot 'deploy\secrets\broker-providers' }
$auditFile = Join-Path $repoRoot 'deploy\secrets\migration-audit.jsonl'   # 目录已 gitignore

$results = @()
function Check([string]$name, [bool]$ok, [string]$detail = '') {
    $tag = if ($ok) { 'PASS' } else { 'FAIL' }
    $script:results += [pscustomobject]@{ Name = $name; Status = $tag; Detail = $detail }
    $color = if ($ok) { 'Green' } else { 'Red' }
    Write-Host "[$tag] $name $detail" -ForegroundColor $color
}

# ---------- 临时目录（Key 经文件直传，用后即删） ----------
$tmpDir = Join-Path $env:TEMP 'migrate-plaintext'
if (Test-Path $tmpDir) { Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$ctrTmp = '/tmp/migrate-plaintext'

function Write-JsonFile([string]$file, [object]$obj) {
    [System.IO.File]::WriteAllText($file, ($obj | ConvertTo-Json -Depth 8 -Compress), (New-Object System.Text.UTF8Encoding($false)))
}

function Get-B64Url([byte[]]$bytes) {
    return ([Convert]::ToBase64String($bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

# 指纹：SHA-256 前 8 位十六进制（不可逆推，用于审计核对）
function Get-KeyFingerprint([string]$key) {
    $sha = [System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($key))
    return (($sha[0..3] | ForEach-Object { $_.ToString('x2') }) -join '')
}

# 内部令牌（HS256，claims 契约同 gateway-admin-service auth.go）
function New-InternalToken([string]$sub, [string]$secret) {
    $now = [int][double]::Parse((Get-Date -UFormat %s))
    $header = '{"alg":"HS256","typ":"JWT"}'
    $payload = '{"sub":"' + $sub + '","role":"admin","iss":"higress-console","aud":"gateway-admin-service","iat":' + $now + ',"exp":' + ($now + 300) + '}'
    $signingInput = (Get-B64Url ([Text.Encoding]::UTF8.GetBytes($header))) + '.' + (Get-B64Url ([Text.Encoding]::UTF8.GetBytes($payload)))
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes($secret)
    $sig = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($signingInput))
    return $signingInput + '.' + (Get-B64Url $sig)
}

# 控制台 API（容器内 console；body 经 docker cp 文件直传）
function Invoke-ConsoleApi([string]$method, [string]$path, [object]$body) {
    $reqHost = Join-Path $tmpDir 'creq.json'
    if ($null -ne $body) { Write-JsonFile $reqHost $body; docker cp $reqHost "${Container}:${ctrTmp}-req.json" 2>$null | Out-Null }
    $dataArg = ''
    if ($null -ne $body) { $dataArg = "--data-binary @${ctrTmp}-req.json" }
    $cmd = "curl -s -m 60 -X $method -H Content-Type:application/json -b ${ctrTmp}.cookies -c ${ctrTmp}.cookies $dataArg -o ${ctrTmp}-resp.json -w %{http_code} http://127.0.0.1:${ConsolePort}$path"
    $code = docker exec $Container sh -c $cmd 2>$null
    $respHost = Join-Path $tmpDir 'cresp.json'
    docker cp "${Container}:${ctrTmp}-resp.json" $respHost 2>$null | Out-Null
    $text = ''
    if (Test-Path $respHost) { $text = [System.IO.File]::ReadAllText($respHost) }
    return [pscustomobject]@{ Code = "$code".Trim(); Body = $text }
}

# broker 凭据 API（宿主直连管理面；Key 经 --data-binary @file 直传，不进命令行）
function Invoke-BrokerApi([string]$method, [string]$path, [object]$body) {
    $token = New-InternalToken $User $JwtSecret
    $hdr = Join-Path $tmpDir 'bh.txt'
    [System.IO.File]::WriteAllText($hdr, "Authorization: Bearer $token`nContent-Type: application/json`n", (New-Object System.Text.UTF8Encoding($false)))
    $out = Join-Path $tmpDir 'bout.json'
    if ($null -ne $body) {
        $bf = Join-Path $tmpDir 'breq.json'
        Write-JsonFile $bf $body
        $code = & curl.exe -s -m 30 -X $method -H "@$hdr" --data-binary "@$bf" -o $out -w '%{http_code}' "$BrokerBase$path" 2>$null
    } else {
        $code = & curl.exe -s -m 30 -X $method -H "@$hdr" -o $out -w '%{http_code}' "$BrokerBase$path" 2>$null
    }
    $text = ''
    if (Test-Path $out) { $text = [System.IO.File]::ReadAllText($out) }
    return [pscustomobject]@{ Code = "$code".Trim(); Body = $text }
}

# 从 broker 凭据文件读回 Key（回滚用；文件即 M2 的 Key 存放处）
function Read-CredentialKey([string]$name) {
    $f = Join-Path $SecretsDir "$name.env"
    if (-not (Test-Path $f)) { return '' }
    $upper = $name.ToUpper()
    foreach ($line in (Get-Content $f -Encoding UTF8)) {
        if ($line -match "^ADMIN_BROKER_KEY_$([regex]::Escape($upper))=(.+)$") { return $Matches[1].Trim() }
    }
    return ''
}

# 审计登记（JSONL 追加；不含明文 Key，仅指纹）
function Write-Audit([string]$action, [string]$prov, [string]$brokerKey, [string]$fingerprint,
    [string]$fromUrl, [string]$toUrl, [int]$tokenCount, [string]$note) {
    $entry = [ordered]@{
        ts             = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        action         = $action
        provider       = $prov
        brokerKey      = $brokerKey
        operator       = $Operator
        keyFingerprint = $fingerprint
        fromCustomUrl  = $fromUrl
        toCustomUrl    = $toUrl
        tokenCount     = $tokenCount
        note           = $note
    }
    $dir = Split-Path -Parent $auditFile
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    Add-Content -Path $auditFile -Value ($entry | ConvertTo-Json -Compress) -Encoding UTF8
}

function Get-BrokerKey([string]$name) { return $name }   # 1:1 映射：provider 名 = broker provider 标识

function Get-BrokerCustomUrl([string]$brokerKey) { return "$BrokerPublicBase/llm-broker/$brokerKey/v1/chat/completions" }

# 由原 customUrl 推导厂商上游基址（scheme://host）
function Get-Upstream([string]$customUrl) {
    try { $u = [uri]$customUrl; return "$($u.Scheme)://$($u.Authority)" } catch { return '' }
}

Write-Host '===== 存量明文 provider 迁移（M2 B-1） =====' -ForegroundColor Cyan
Write-Host "Mode=$Mode Provider=$(if($Provider){$Provider}else{'(全部)'}) Operator=$(if($Operator){$Operator}else{'(未指定)'})"
Write-Host "Console=:$ConsolePort Broker=$BrokerBase BrokerPublicBase=$BrokerPublicBase SecretsDir=$SecretsDir"

# ---------- 预检 ----------
Write-Host "`n[预检]" -ForegroundColor Yellow
if ($Mode -ne 'dry-run') {
    if (-not $JwtSecret) { $JwtSecret = [string]$env:ADMIN_SVC_JWT_SECRET }
    Check 'P1 apply/rollback 需提供 -JwtSecret（与服务 ADMIN_SVC_JWT_SECRET 一致）' ([bool]$JwtSecret)
    Check 'P2 审计操作人已指定（-Operator）' ([bool]$Operator) '(留痕要求，缺省拒绝执行)'
    if (-not $Yes) {
        Write-Host "`n即将执行 $Mode（会改写控制台 provider 配置）。确认请加 -Yes 重跑。" -ForegroundColor Yellow
        exit 1
    }
}
$login = Invoke-ConsoleApi 'POST' '/session/login' @{ username = $User; password = $Pass }
Check 'P3 控制台登录会话' ($login.Code -eq '200' -or $login.Code -eq '201') "(code=$($login.Code))"
$health = & curl.exe -s -m 5 "$BrokerBase/healthz" 2>$null
Check 'P4 broker/管理面服务就绪' ("$health".Trim() -eq 'ok') "(healthz=$("$health".Trim()) 提示：A-2 起管理面在 :19095，broker 中转在 :19096)"

if (($results | Where-Object { $_.Status -eq 'FAIL' }).Count -gt 0) {
    Write-Host "`n预检未通过，终止。" -ForegroundColor Red
    if (Test-Path $tmpDir) { Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue }
    exit 1
}

# ---------- 枚举 ----------
Write-Host "`n[枚举]" -ForegroundColor Yellow
$listResp = Invoke-ConsoleApi 'GET' '/v1/ai/providers' $null
$all = @()
if ($listResp.Code -eq '200' -and $listResp.Body) {
    try {
        $parsed = $listResp.Body | ConvertFrom-Json
        # 控制台响应为信封 {success,message,data}；兼容裸数组与 {providers:[...]} 两种形态
        if ($parsed -is [array]) { $all = @($parsed) }
        elseif ($parsed.PSObject.Properties.Name -contains 'data') { $all = @($parsed.data) }
        else { $all = @($parsed) }
        if ($all.Count -gt 0 -and $all[0] -and ($all[0].PSObject.Properties.Name -contains 'providers')) { $all = @($all[0].providers) }
    } catch { $all = @() }
}
Check 'E1 读取控制台 provider 列表' ($listResp.Code -eq '200') "(count=$($all.Count))"

$plan = @()
foreach ($p in $all) {
    if (-not $p -or -not $p.name) { continue }
    if ($Provider -and $p.name -ne $Provider) { continue }
    $tokens = @()
    if ($p.tokens) { $tokens = @($p.tokens) }
    $customUrl = ''
    if ($p.rawConfigs -and $p.rawConfigs.openaiCustomUrl) { $customUrl = "$($p.rawConfigs.openaiCustomUrl)" }
    $isHosted = $customUrl -like "*/llm-broker/*"
    $row = [pscustomobject]@{ Name = $p.name; Type = $p.type; Protocol = $p.protocol; Tokens = $tokens; CustomUrl = $customUrl; Hosted = $isHosted }
    if ($Mode -eq 'rollback') {
        if ($isHosted) { $plan += $row }
    } else {
        if ($tokens.Count -gt 0 -and -not $isHosted) { $plan += $row }
    }
}

if ($plan.Count -eq 0) {
    Write-Host "  无需处理（$Mode 下的匹配项为 0）。" -ForegroundColor DarkGray
    if (Test-Path $tmpDir) { Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue }
    exit 0
}

# ---------- 计划展示（Key 仅指纹） ----------
Write-Host "`n[计划]（$($plan.Count) 项）" -ForegroundColor Yellow
foreach ($item in $plan) {
    $bk = Get-BrokerKey $item.Name
    $fp = if ($item.Tokens.Count -gt 0) { Get-KeyFingerprint ([string]$item.Tokens[0]) } else { '-' }
    Write-Host ("  {0,-20} key={1} token数={2}" -f $item.Name, $fp, $item.Tokens.Count)
    if ($Mode -eq 'rollback') {
        Write-Host ("      回滚：{0}  →  明文 tokens + 还原 customUrl（来自审计记录）" -f $item.CustomUrl) -ForegroundColor DarkGray
    } else {
        Write-Host ("      迁移：{0}  →  {1}（tokens 清空）" -f $item.CustomUrl, (Get-BrokerCustomUrl $bk)) -ForegroundColor DarkGray
    }
}

if ($Mode -eq 'dry-run') {
    Write-Host "`ndry-run 结束（无副作用）。确认无误后执行：" -ForegroundColor Green
    Write-Host "  powershell -ExecutionPolicy Bypass -File scripts\migrate-plaintext-providers.ps1 -Mode apply -Yes -JwtSecret <secret> -Operator <name>" -ForegroundColor DarkGray
    if (Test-Path $tmpDir) { Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue }
    exit 0
}

# ---------- 执行 ----------
Write-Host "`n[执行 $Mode]" -ForegroundColor Yellow
foreach ($item in $plan) {
    $name = $item.Name
    $bk = Get-BrokerKey $name
    $toUrl = Get-BrokerCustomUrl $bk
    $p = $item   # 下方 provider 还原/更新按控制台字段 type/protocol 组包
    try {
        if ($Mode -eq 'apply') {
            $key = [string]$item.Tokens[0]
            $upstream = Get-Upstream $item.CustomUrl
            if (-not $upstream) { throw "无法从原 customUrl 推导厂商上游：$($item.CustomUrl)" }
            $r1 = Invoke-BrokerApi 'POST' "/v1/adminext/broker-providers/$bk" @{ upstream = $upstream; key = $key }
            if ($r1.Code -ne '200') { throw "broker 凭据写入失败 code=$($r1.Code) $($r1.Body)" }
            $res1 = $r1.Body | ConvertFrom-Json
            if ($res1.customUrl) { $toUrl = "$($res1.customUrl)" }

            $r2 = Invoke-ConsoleApi 'PUT' "/v1/ai/providers/$name" @{
                name       = $name
                type       = $p.type
                protocol   = $p.protocol
                tokens     = @()
                rawConfigs = @{ openaiCustomUrl = $toUrl }
            }
            if ($r2.Code -ne '200' -and $r2.Code -ne '201') { throw "控制台 provider 更新失败 code=$($r2.Code) $($r2.Body)" }

            Write-Audit 'migrate' $name $bk (Get-KeyFingerprint $key) $item.CustomUrl $toUrl $item.Tokens.Count 'CR 已无明文令牌'
            Check "迁移 $name" $true "(broker=$bk, customUrl→broker)"
        } else {
            $key = Read-CredentialKey $bk
            if (-not $key) { throw "broker 凭据文件缺失或不可读：$SecretsDir\$bk.env（无法回滚）" }
            $origUrl = ''
            if (Test-Path $auditFile) {
                foreach ($line in (Get-Content $auditFile -Encoding UTF8)) {
                    if (-not $line.Trim()) { continue }
                    try { $e = $line | ConvertFrom-Json } catch { continue }
                    if ($e.provider -eq $name -and $e.action -eq 'migrate' -and $e.fromCustomUrl) { $origUrl = "$($e.fromCustomUrl)" }
                }
            }
            if (-not $origUrl) { throw "审计记录中未找到 $name 的原 customUrl，拒绝回滚（避免写入错误上游）" }

            $r2 = Invoke-ConsoleApi 'PUT' "/v1/ai/providers/$name" @{
                name       = $name
                type       = $p.type
                protocol   = $p.protocol
                tokens     = @($key)
                rawConfigs = @{ openaiCustomUrl = $origUrl }
            }
            if ($r2.Code -ne '200' -and $r2.Code -ne '201') { throw "控制台 provider 还原失败 code=$($r2.Code) $($r2.Body)" }

            Write-Audit 'rollback' $name $bk (Get-KeyFingerprint $key) $toUrl $origUrl 1 '明文已写回 CR（高敏变更）；broker 凭据保留以便再次迁移'
            Check "回滚 $name" $true "(customUrl 还原，broker 凭据保留)"
        }
    } catch {
        Check "$Mode $name" $false $_.Exception.Message
    }
}

# ---------- 汇总 ----------
Write-Host "`n===== 汇总 =====" -ForegroundColor Cyan
$pass = ($results | Where-Object { $_.Status -eq 'PASS' }).Count
$fail = ($results | Where-Object { $_.Status -eq 'FAIL' }).Count
Write-Host "PASS=$pass FAIL=$fail（审计记录：$auditFile）" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host "后续验证：脚本 demo-broker-secret-pilot.ps1（推理经 broker 通路 200 即迁移成功）" -ForegroundColor DarkGray

# 清理临时请求体（含 Key 的 JSON 一并删除）
docker exec $Container sh -c "rm -f ${ctrTmp}-req.json ${ctrTmp}-resp.json ${ctrTmp}.cookies" 2>$null | Out-Null
if (Test-Path $tmpDir) { Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue }

if ($fail -gt 0) { exit 1 }
exit 0
