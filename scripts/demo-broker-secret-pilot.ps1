# demo-broker-secret-pilot.ps1 - apiTokens Secret 化验证（路线丙·内部凭据 broker）
#
# 覆盖两批能力：
#   M1 试点（A–H）：broker 中转正确性（Key 覆盖注入 / 路径白名单 / request_id / SSE / CR 无明文）
#   M2 A-1（I）：凭据托管链路（CRUD / 原子落盘 / 热加载即时生效 / 最小角色控制 / 漂移检测）
#
# 自动化验证场景并打印 PASS/FAIL：
#   A. 预检               容器/网关/控制台会话/cmaas.env；broker 服务就绪（本脚本管理生命周期：
#                         重启为新构建 + 凭据目录注入，fail-closed）+ 指标端点含新指标族
#   B. 无 token provider  控制台 API 建 provider（tokens=[]，openaiCustomUrl→broker）/路由（幂等）
#   C. CR 无 Key 断言     ai-proxy.internal.yaml 中 phala-broker 条目：无 apiTokens/无真实 Key/
#                         customUrl 精确一致；全文件真实 Key 扫描（条目外命中=存量明文，WARN 不算 FAIL）
#   D. 一致性自检         CR customUrl 形态 = http://host.docker.internal:19095/llm-broker/phala/...
#   E. 读接口无明文       GET /v1/ai/providers/phala-broker：无真实 Key 且 tokens 为空
#   F. 经 broker 推理     网关 /phala-broker：非流式 200 非空；SSE 200 data 行 + 内容非空
#   G. 白名单/未知        白名单外路径 404；未知 provider 404；404 响应带 X-Request-ID（S-3）
#   H. 指标汇总           gateway_admin_broker_requests_total 计数打印
#   I. A-1 凭据托管       直连 Go 服务（自签内部令牌）：
#                         I1-I2 写入受理 + customUrl/指纹（**不回显 Key**）
#                         I3    凭据文件原子落盘（无 .tmp 残留）
#                         I4    热加载即时生效（route 表含新 provider，指标 path_denied 证明，不触上游）
#                         I5-I6 列表/详情无明文、含指纹
#                         I7    参数校验（http 上游 / provider 名非法 → 400）
#                         I8    最小角色控制（auditor 写 403 / 读 200；admin 写 200）
#                         I9    删除 + 联动告警 + 路由即时摘除
#                         I10   漂移检测（删凭据 → orphanDetected；恢复 → 消除）
#                         I11   console→Go 转发目标配置状态（信息项）
#
# 边界（如实）：
#   - broker 信任边界 = 集群内网（演示 = 本机端口）+ provider/路径双重白名单；NetworkPolicy 为 A-2；
#   - 存量明文 provider 不受保护，B-1 迁移；
#   - I 段直连 Go 服务：console Java 转发层未在本脚本内配置 ADMIN_SVC_TARGET（见 I11），
#     故以自签内部令牌覆盖 Go 侧全部行为；UI 链路验证需按升级手册 §7.1 启动控制台后手工过一遍页面。
#
# 前置：higress-standalone 容器运行中（:8080 网关、:18001 fork console）；deploy/secrets/cmaas.env 已配置；
#       Go 工具链可用（本脚本会本地构建 gateway-admin-service）。
# 用法：powershell -ExecutionPolicy Bypass -File scripts\demo-broker-secret-pilot.ps1 [-SkipProvision]
# 退出码：0 = 全部通过；1 = 存在失败（可接 CI）。
#
# 注：本脚本为 UTF-8 with BOM；含中文，勿改为无 BOM 保存（PS 5.1 按 ANSI 解析会坏语法）。

param(
    [string]$Container = 'higress-chain-control-plane',
    [int]$ConsolePort = 18001,
    [string]$Gateway = 'http://127.0.0.1:8080',
    [int]$BrokerPort = 19095,
    [string]$BrokerHostFromGateway = 'host.docker.internal:19095',
    [string]$ProviderName = 'phala-broker',
    [string]$BrokerRouteKey = 'phala',
    [string]$RouteName = 'phala-broker-demo',
    [string]$RoutePath = '/phala-broker',
    [string]$User = 'adminExtSmoke',
    [string]$Pass = 'Adm1n-Smoke-2026',
    [string]$AdminUser = 'adminExtSmoke',
    [string]$AuditorUser = 'auditorSmoke',
    [switch]$SkipProvision
)

$ErrorActionPreference = 'Stop'

$results = @()
$v2Note = ''   # V2 观察（console REST 对空 apiTokens 的行为）
$v1Note = ''   # V1 观察（customUrl 多路径语义）

function Check([string]$name, [bool]$ok, [string]$detail = '') {
    $tag = if ($ok) { 'PASS' } else { 'FAIL' }
    $script:results += [pscustomobject]@{ Name = $name; Status = $tag; Detail = $detail }
    if ($ok) { Write-Host "[$tag] $name $detail" -ForegroundColor Green }
    else { Write-Host "[$tag] $name $detail" -ForegroundColor Red }
}

function Warn([string]$name, [string]$detail) {
    $script:results += [pscustomobject]@{ Name = $name; Status = 'WARN'; Detail = $detail }
    Write-Host "[WARN] $name $detail" -ForegroundColor Yellow
}

function Test-Port([int]$port) {
    return [bool](netstat -ano | Select-String ":$port" | Select-String 'LISTENING')
}

# ---------- cmaas.env（密钥源，gitignored） ----------
$repoRoot = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $repoRoot 'deploy\secrets\cmaas.env'
$cmaas = @{}
$haveEnv = Test-Path $envFile
if ($haveEnv) {
    # -Encoding UTF8：防 PS 5.1 ANSI 误码吞行丢密钥（同 demo-vendor-activation.ps1）
    Get-Content $envFile -Encoding UTF8 | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith('#')) {
            $k, $v = $line -split '=', 2
            if ($k -and $v) { $cmaas[$k.Trim()] = $v.Trim() }
        }
    }
}
$apiKey = if ($cmaas['CMAAS_API_KEY']) { $cmaas['CMAAS_API_KEY'] } else { '' }
$cmaasUrl = if ($cmaas['CMAAS_URL']) { $cmaas['CMAAS_URL'].TrimEnd('/') } else { '' }
$cmaasModel = if ($cmaas['CMAAS_MODEL']) { $cmaas['CMAAS_MODEL'] } else { '' }

$crFile = Join-Path $repoRoot 'higress-standalone\wasmplugins\ai-proxy.internal.yaml'
$brokerPublicBase = "http://$BrokerHostFromGateway"
$expectedCustomUrl = "$brokerPublicBase/llm-broker/$BrokerRouteKey/v1/chat/completions"

# ---------- 临时目录（请求体经文件直传，规避 PS 内联引号/密钥入命令行） ----------
$tmpDir = Join-Path $env:TEMP 'broker-secret-pilot'
if (Test-Path $tmpDir) {
    # 残留 broker 进程持有的 exe 可能删不掉，忽略单文件失败，尽量清空
    Get-ChildItem $tmpDir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne 'gateway-admin-service.exe' } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$ctrTmp = '/tmp/broker-pilot'
$secretsDir = Join-Path $tmpDir 'broker-secrets'

function Write-JsonFile([string]$file, [object]$obj) {
    [System.IO.File]::WriteAllText($file, ($obj | ConvertTo-Json -Depth 8 -Compress), (New-Object System.Text.UTF8Encoding($false)))
}

# 写入 broker 凭据文件（与 gateway-admin-service broker_secret.go 格式一致；供 I 段前预置主凭据）
function Write-ProviderEnvFile([string]$dir, [string]$name, [string]$upstream, [string]$key, [string]$paths) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $upper = $name.ToUpper()
    $content = "ADMIN_BROKER_UPSTREAM_$upper=$upstream`nADMIN_BROKER_KEY_$upper=$key`nADMIN_BROKER_PATHS_$upper=$paths`n"
    [System.IO.File]::WriteAllText((Join-Path $dir "$name.env"), $content, (New-Object System.Text.UTF8Encoding($false)))
}

# 容器内 console API 调用（同 demo-vendor-activation.ps1 既有惯例，docker cp 文件直传）
function Invoke-ConsoleApi([string]$method, [string]$path, [object]$body) {
    $reqHost = Join-Path $tmpDir 'req.json'
    if ($null -ne $body) { Write-JsonFile $reqHost $body }
    if ($null -ne $body) { docker cp $reqHost "${Container}:${ctrTmp}-req.json" 2>$null | Out-Null }
    $dataArg = ''
    if ($null -ne $body) { $dataArg = "--data-binary @${ctrTmp}-req.json" }
    $cmd = "curl -s -m 60 -X $method -H Content-Type:application/json -b ${ctrTmp}.cookies -c ${ctrTmp}.cookies $dataArg -o ${ctrTmp}-resp.json -w %{http_code} http://127.0.0.1:${ConsolePort}$path"
    $code = docker exec $Container sh -c $cmd 2>$null
    $respHost = Join-Path $tmpDir 'resp.json'
    docker cp "${Container}:${ctrTmp}-resp.json" $respHost 2>$null | Out-Null
    $bodyText = ''
    if (Test-Path $respHost) { $bodyText = [System.IO.File]::ReadAllText($respHost) }
    return [pscustomobject]@{ Code = "$code".Trim(); Body = $bodyText }
}

function Upsert-Json([string]$api, [string]$resourceName, [object]$body) {
    # POST 为主；409/500（同名已存在）→ PUT 幂等覆盖
    $r = Invoke-ConsoleApi 'POST' $api $body
    if ($r.Code -eq '409' -or $r.Code -eq '500') {
        $r = Invoke-ConsoleApi 'PUT' "$api/$resourceName" $body
    }
    return $r
}

# ---------- 内部令牌自签（HS256，与 auth.go claims 契约一致） ----------
function Get-B64Url([byte[]]$bytes) {
    return ([Convert]::ToBase64String($bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function New-InternalToken([string]$sub, [string]$role, [string]$secret) {
    $now = [int][double]::Parse((Get-Date -UFormat %s))
    $header = '{"alg":"HS256","typ":"JWT"}'
    $payload = '{"sub":"' + $sub + '","role":"' + $role + '","iss":"higress-console","aud":"gateway-admin-service","iat":' + $now + ',"exp":' + ($now + 300) + '}'
    $signingInput = (Get-B64Url ([Text.Encoding]::UTF8.GetBytes($header))) + '.' + (Get-B64Url ([Text.Encoding]::UTF8.GetBytes($payload)))
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes($secret)
    $sig = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($signingInput))
    return $signingInput + '.' + (Get-B64Url $sig)
}

# 直连 gateway-admin-service 凭据端点（url = 完整地址；Bearer = 自签内部令牌）
#
# 注：PS 5.1 的 Invoke-WebRequest **禁止经 -Headers 传 Content-Type**（受限头，
# 会抛 ParameterBindingException 且无 Response → 表现为 code=0），故用独立 -ContentType 参数。
function Invoke-BrokerApi([string]$method, [string]$url, [object]$body, [string]$sub, [string]$role) {
    $token = New-InternalToken $sub $role $script:svcSecret
    $authHeaders = @{ Authorization = "Bearer $token" }
    try {
        if ($null -ne $body) {
            $raw = $body | ConvertTo-Json -Depth 6 -Compress
            $resp = Invoke-WebRequest -UseBasicParsing -Method $method -Uri $url `
                -Headers $authHeaders -ContentType 'application/json' -Body $raw -TimeoutSec 30
        } else {
            $resp = Invoke-WebRequest -UseBasicParsing -Method $method -Uri $url `
                -Headers $authHeaders -TimeoutSec 30
        }
        return [pscustomobject]@{ Code = [int]$resp.StatusCode; Body = "$($resp.Content)" }
    } catch {
        $code = 0; $text = ''
        $ex = $_.Exception
        if ($ex.Response) {
            $code = [int]$ex.Response.StatusCode
            try {
                $stream = $ex.Response.GetResponseStream()
                $text = (New-Object System.IO.StreamReader($stream)).ReadToEnd()
            } catch { $text = '' }
        } else {
            # 无响应 = 请求未发出/传输失败，暴露异常类型与消息便于定位
            $text = "transport[" + $ex.GetType().Name + "]: " + $ex.Message
        }
        return [pscustomobject]@{ Code = $code; Body = $text }
    }
}

# ---------- CR provider 条目解析（ai-proxy.internal.yaml spec.defaultConfig.providers） ----------
function Get-ProviderBlocks([string]$yaml) {
    $blocks = @()
    $lines = $yaml -split "`r?`n"
    $cur = $null
    foreach ($ln in $lines) {
        if ($ln -match '^    - ') {
            if ($cur) { $blocks += ,$cur }
            $cur = @($ln)
        } elseif ($null -ne $cur) {
            if ($ln -match '^  \S') { $blocks += ,$cur; $cur = $null }
            else { $cur += $ln }
        }
    }
    if ($cur) { $blocks += ,$cur }
    $out = @()
    foreach ($b in $blocks) {
        $text = $b -join "`n"
        if ($text -match '(?m)^[\s-]*id:\s*(\S+)') {
            $out += [pscustomobject]@{ Id = $Matches[1]; Block = $text }
        }
    }
    # 直接返回数组（不用一元数组包裹），保证管道调用时 Where-Object 逐元素过滤。
    return $out
}

function Test-EntryApiTokensEmpty([string]$block) {
    if ($block -match '(?m)^\s*apiTokens:\s*(\S.*)$') {
        $inline = $Matches[1].Trim()
        return ($inline -eq '[]' -or $inline -eq 'null' -or $inline -eq '~')
    }
    if ($block -match '(?m)^\s*apiTokens:\s*$') {
        $inList = $false
        foreach ($ln in ($block -split "`n")) {
            if ($ln -match '^\s*apiTokens:\s*$') { $inList = $true; continue }
            if ($inList) {
                if ($ln -match '^\s*-\s+\S') { return $false }
                if ($ln -match '^\s{0,4}\S') { break }
            }
        }
        return $true
    }
    return $true
}

function Get-PhalaMetricSum([string]$metrics) {
    $sum = 0
    foreach ($m in [regex]::Matches($metrics, 'gateway_admin_broker_requests_total\{provider="phala",[^\n]*\}\s+(\d+)')) {
        $sum += [int]$m.Groups[1].Value
    }
    return $sum
}

function Get-Metrics() {
    return ((& curl.exe -s -m 5 "$BrokerBase/metrics" 2>$null) -join "`n")
}

$BrokerBase = "http://127.0.0.1:$BrokerPort"
$svcSecret = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N').Substring(0, 8)

Write-Host '===== apiTokens Secret 化验证（路线丙·内部凭据 broker；M1 试点 + M2 A-1） =====' -ForegroundColor Cyan
Write-Host "Provider=$ProviderName BrokerKey=$BrokerRouteKey RoutePath=$RoutePath BrokerBase=$BrokerBase"
Write-Host "AdminUser=$AdminUser AuditorUser=$AuditorUser SecretsDir=$secretsDir"
$brokerReady = $false
$svcProc = $null

try {
    # ---------- A. 预检 ----------
    Write-Host "`n[A] 预检" -ForegroundColor Yellow
    $ctrRunning = [bool](docker inspect -f '{{.State.Running}}' $Container 2>$null | Select-Object -First 1 | Where-Object { $_ -eq 'true' })
    Check 'A1 higress-standalone 容器运行中' $ctrRunning
    Check 'A2 网关 :8080 就绪' (Test-Port 8080)
    Check 'A3 cmaas.env 可读且密钥配置在位' ($haveEnv -and $apiKey.Length -ge 8 -and $cmaasUrl -and $cmaasModel) `
        "(key_len=$($apiKey.Length)（不回显）, model=$cmaasModel)"
    if ($ctrRunning) {
        $r = Invoke-ConsoleApi 'POST' '/session/login' @{ username = $User; password = $Pass }
        Check 'A4 fork 控制台登录会话（:18001）' ($r.Code -eq '201' -or $r.Code -eq '200') "(code=$($r.Code))"
    }

    # A5 broker 服务：本脚本管理生命周期（停止旧实例 → 构建 → 凭据目录 + 角色白名单注入启动）
    $adminExe = Join-Path $tmpDir 'gateway-admin-service.exe'
    $oldProc = Get-Process -Name 'gateway-admin-service' -ErrorAction SilentlyContinue
    if ($oldProc) {
        Write-Host ("  停止既有 gateway-admin-service 实例（PID=" + (($oldProc | ForEach-Object { $_.Id }) -join ',') + "），由本脚本统一管理") -ForegroundColor DarkGray
        $oldProc | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 800
    }
    $buildOk = $false
    if (Test-Path $adminExe) {
        $buildOk = $true   # 复用已构建产物（同一次会话内重跑）
    } else {
        Push-Location $repoRoot
        # -mod=mod：仓库根 vendor/ 与 go.mod 存在已知不一致（wasm/tiktoken 等包），
        # gateway-admin-service 为根模块子包（无独立 go.mod），需绕过 vendor 校验。
        & go build -mod=mod -o $adminExe ./gateway/gateway-admin-service
        $buildOk = ($LASTEXITCODE -eq 0 -and (Test-Path $adminExe))
        Pop-Location
    }

    if (-not $buildOk) {
        Check 'A5 broker 服务就绪' $false '(go build 失败，见上输出)'
    } else {
        # 预置主凭据（供 B–H 主链路；I 段将在此之上做轮换/删除/恢复）
        Write-ProviderEnvFile $secretsDir $BrokerRouteKey $cmaasUrl $apiKey '/v1/chat/completions,/v1/models,/v1/embeddings'

        # 环境变量经进程级注入后立即清除（子进程创建时已继承副本，不残留会话）
        [Environment]::SetEnvironmentVariable('ADMIN_SVC_JWT_SECRET', $svcSecret, 'Process')
        [Environment]::SetEnvironmentVariable('ADMIN_SVC_LISTEN', ":$BrokerPort", 'Process')
        [Environment]::SetEnvironmentVariable('ADMIN_SVC_ROLE_ADMINS', $AdminUser, 'Process')
        [Environment]::SetEnvironmentVariable('ADMIN_BROKER_SECRETS_DIR', $secretsDir, 'Process')
        [Environment]::SetEnvironmentVariable('ADMIN_BROKER_PUBLIC_BASE', $brokerPublicBase, 'Process')
        [Environment]::SetEnvironmentVariable('ADMIN_BROKER_CR_FILE', $crFile, 'Process')
        $svcProc = Start-Process -FilePath $adminExe -WindowStyle Hidden -PassThru
        foreach ($n in @('ADMIN_SVC_JWT_SECRET', 'ADMIN_SVC_LISTEN', 'ADMIN_SVC_ROLE_ADMINS', 'ADMIN_BROKER_SECRETS_DIR', 'ADMIN_BROKER_PUBLIC_BASE', 'ADMIN_BROKER_CR_FILE')) {
            [Environment]::SetEnvironmentVariable($n, $null, 'Process')
        }
        $healthOk = $false
        for ($i = 0; $i -lt 15; $i++) {
            try {
                $h = Invoke-WebRequest -UseBasicParsing -Uri "$BrokerBase/healthz" -TimeoutSec 2
                if ("$($h.Content)".Trim() -eq 'ok') { $healthOk = $true; break }
            } catch { Start-Sleep -Seconds 1 }
        }
        Check 'A5 broker 服务就绪（凭据目录模式）' $healthOk "(新启动 PID=$($svcProc.Id)，保持运行；如需停止：Stop-Process -Id $($svcProc.Id))"
    }
    $brokerReady = Test-Port $BrokerPort

if ($brokerReady) {
    # A6 指标端点含新指标族（含 reload 失败计数）
    $m = Get-Metrics
    Check 'A6 broker 指标端点含 M2 指标族' (($m -match 'gateway_admin_broker_requests_total') -and ($m -match 'gateway_admin_broker_config_reload_failed_total')) '(旧版服务请重启为新构建)'

    # ---------- B. 建 provider/route（无 token 形态，幂等） ----------
    Write-Host "`n[B] 建 provider/route（无 token 形态，openaiCustomUrl → broker）" -ForegroundColor Yellow
    $providerBody = @{
        name       = $ProviderName
        type       = 'openai'
        protocol   = 'openai/v1'
        tokens     = @()
        rawConfigs = @{ openaiCustomUrl = $expectedCustomUrl }
    }
    if (-not $SkipProvision) {
        $r = Upsert-Json '/v1/ai/providers' $ProviderName $providerBody
        $accepted = ($r.Code -eq '200' -or $r.Code -eq '201')
        if (-not $accepted) {
            $snippet = $r.Body
            if ($snippet.Length -gt 120) { $snippet = $snippet.Substring(0, 120) }
            $v2Note = "console REST 拒绝空 apiTokens（code=$($r.Code)，body 摘要：$snippet）→ 回退手工 CR 供给，之后用 -SkipProvision 重跑断言段"
            Check 'B1 provider 创建受理（tokens=[]）' $false "(code=$($r.Code)) $v2Note"
        } else {
            $v2Note = "console REST 受理空 apiTokens（code=$($r.Code)）"
            Check 'B1 provider 创建受理（tokens=[]）' $true "(code=$($r.Code))"
        }
    } else {
        $v2Note = '跳过 provisioning（-SkipProvision，手工 CR 供给形态）'
        Write-Host "  [跳过] B1 provider 创建（$v2Note）" -ForegroundColor DarkGray
    }
    $r = Invoke-ConsoleApi 'GET' "/v1/ai/providers/$ProviderName" $null
    Check 'B2 provider 条目在位且 customUrl 指向 broker' ($r.Code -eq '200' -and $r.Body.Contains($expectedCustomUrl)) "(code=$($r.Code))"
    if (-not $SkipProvision) {
        $routeBody = @{
            name          = $RouteName
            pathPredicate = @{ matchType = 'PRE'; matchValue = $RoutePath }
            upstreams     = @(@{ provider = $ProviderName; weight = 100 })
        }
        $r = Upsert-Json '/v1/ai/routes' $RouteName $routeBody
        Check 'B3 路由创建受理' ($r.Code -eq '200' -or $r.Code -eq '201') "(code=$($r.Code))"
    }
    $r = Invoke-ConsoleApi 'GET' "/v1/ai/routes/$RouteName" $null
    Check 'B4 路由条目在位' ($r.Code -eq '200' -and $r.Body -match ('"name"\s*:\s*"' + $RouteName + '"')) "(code=$($r.Code))"

    # ---------- C. CR/快照无 Key 断言 ----------
    Write-Host "`n[C] CR/快照无 Key 断言（ai-proxy.internal.yaml）" -ForegroundColor Yellow
    $pb = $null
    for ($i = 0; $i -lt 15 -and $null -eq $pb; $i++) {
        if (Test-Path $crFile) {
            $yaml = [System.IO.File]::ReadAllText($crFile)
            $pb = Get-ProviderBlocks $yaml | Where-Object { $_.Id -eq $ProviderName } | Select-Object -First 1
        }
        if ($null -eq $pb) { Start-Sleep -Seconds 1 }
    }
    Check 'C1 CR 中 phala-broker 条目在位' ($null -ne $pb) "(file=$crFile)"
    if ($null -ne $pb) {
        $urlInCr = ''
        for ($j = 0; $j -lt 10; $j++) {
            if ($pb.Block -match '(?m)^\s*openaiCustomUrl:\s*(\S+)') {
                $urlInCr = $Matches[1]
                break
            }
            Start-Sleep -Seconds 1
            if (Test-Path $crFile) {
                $yaml = [System.IO.File]::ReadAllText($crFile)
                $pb = Get-ProviderBlocks $yaml | Where-Object { $_.Id -eq $ProviderName } | Select-Object -First 1
                if ($null -eq $pb) { break }
            }
        }
        Check 'C2 条目无 apiTokens（或为空列表）' (Test-EntryApiTokensEmpty $pb.Block)
        Check 'C3 条目内无真实 Key' (-not $pb.Block.Contains($apiKey))
        $c4Detail = if ($urlInCr) { "got=$urlInCr" } else { "urlInCr 为空" }
        Check 'C4 条目 customUrl 精确一致' ($urlInCr -eq $expectedCustomUrl) $c4Detail

        $yamlAll = [System.IO.File]::ReadAllText($crFile)
        $totalHits = [regex]::Matches($yamlAll, [regex]::Escape($apiKey)).Count
        $entryHits = [regex]::Matches($pb.Block, [regex]::Escape($apiKey)).Count
        $otherHits = $totalHits - $entryHits
        if ($otherHits -gt 0) {
            $legacyIds = @()
            foreach ($e in (Get-ProviderBlocks $yamlAll)) {
                if ($e.Id -ne $ProviderName -and $e.Block.Contains($apiKey)) { $legacyIds += $e.Id }
            }
            Warn 'C5 全文件真实 Key 扫描' ("条目外命中 $otherHits 处（存量明文 provider：$($legacyIds -join ', ')，B-1 迁移，非本批次引入）")
        } else {
            Check 'C5 全文件真实 Key 扫描（条目外零命中）' $true '(无存量明文残留)'
        }

        # ---------- D. CR↔broker 一致性自检 ----------
        Write-Host "`n[D] CR↔broker 一致性自检" -ForegroundColor Yellow
        $uriOk = $false
        try {
            $u = [uri]$urlInCr
            $uriOk = ($u.Scheme -eq 'http' -and "$($u.Authority)" -eq $BrokerHostFromGateway -and "$($u.AbsolutePath)" -eq "/llm-broker/$BrokerRouteKey/v1/chat/completions")
        } catch { $uriOk = $false }
        Check 'D1 customUrl 形态 = broker 端点（host/路径/provider 段三重对应）' $uriOk `
            "(host=$BrokerHostFromGateway, provider 段=$BrokerRouteKey)"
    }

    # ---------- E. 读接口无明文 ----------
    Write-Host "`n[E] 读接口无明文（GET /v1/ai/providers/$ProviderName）" -ForegroundColor Yellow
    $r = Invoke-ConsoleApi 'GET' "/v1/ai/providers/$ProviderName" $null
    $noKey = ($r.Code -eq '200') -and ($r.Body.IndexOf($apiKey) -lt 0)
    $tokensEmpty = ($r.Code -eq '200') -and ($r.Body -notmatch '"tokens"\s*:\s*\[\s*"')
    Check 'E1 读接口无真实 Key 且 tokens 为空' ($noKey -and $tokensEmpty) "(code=$($r.Code))"

    # ---------- F. 经 broker 推理（网关 /phala-broker） ----------
    Write-Host "`n[F] 经 broker 推理（ai-proxy → broker → Phala）" -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    $inferFile = Join-Path $tmpDir 'infer.json'
    Write-JsonFile $inferFile @{
        model    = $cmaasModel
        stream   = $false
        messages = @(@{ role = 'user'; content = '用一句话介绍机密计算' })
    }
    $code = ''; $content = ''
    for ($attempt = 0; $attempt -lt 4; $attempt++) {
        $code = & curl.exe -s -m 120 -o $inferFile -w '%{http_code}' -X POST "$Gateway$RoutePath/v1/chat/completions" `
            -H 'Content-Type: application/json' --data-binary "@$inferFile" 2>$null
        if ("$code".Trim() -eq '200') { break }
        Start-Sleep -Seconds 5
    }
    Check 'F1 非流式推理 HTTP 200' ("$code".Trim() -eq '200') "(code=$("$code".Trim()))"
    if ("$code".Trim() -eq '200' -and (Test-Path $inferFile)) {
        try {
            $j = [System.IO.File]::ReadAllText($inferFile) | ConvertFrom-Json
            $content = $j.choices[0].message.content
        } catch { $content = '' }
    }
    Check 'F2 回复明文非空' ($content -ne '')
    if ($content) { Write-Host ("    Phala 回复: " + $content.Substring(0, [Math]::Min(80, $content.Length))) -ForegroundColor DarkCyan }

    $sseFile = Join-Path $tmpDir 'infer-sse.json'
    Write-JsonFile $sseFile @{
        model    = $cmaasModel
        stream   = $true
        messages = @(@{ role = 'user'; content = '用一句话介绍机密计算' })
    }
    $sseCode = & curl.exe -N -s -m 120 -o $sseFile -w '%{http_code}' -X POST "$Gateway$RoutePath/v1/chat/completions" `
        -H 'Content-Type: application/json' --data-binary "@$sseFile" 2>$null
    $sseLines = 0; $sseContent = ''
    if ("$sseCode".Trim() -eq '200' -and (Test-Path $sseFile)) {
        Get-Content $sseFile -Encoding UTF8 | ForEach-Object {
            if ($_ -match '^data:\s*(.+)$') {
                $payload = $Matches[1].Trim()
                if ($payload -ne '[DONE]') {
                    $script:sseLines++
                    try {
                        $j = $payload | ConvertFrom-Json
                        $c = $j.choices[0].delta.content
                        if ($c) { $script:sseContent += $c }
                    } catch {}
                }
            }
        }
    }
    Check 'F3 SSE 流式 200 且内容非空' ("$sseCode".Trim() -eq '200' -and $sseLines -ge 1 -and $sseContent -ne '') "(code=$("$sseCode".Trim()), data 行=$sseLines)"

    # F4 metrics delta 观察（V1c）
    $m0 = Get-PhalaMetricSum (Get-Metrics)
    & curl.exe -s -m 120 -o $inferFile -X POST "$Gateway$RoutePath/v1/chat/completions" `
        -H 'Content-Type: application/json' --data-binary "@$inferFile" 2>$null | Out-Null
    $m1 = Get-PhalaMetricSum (Get-Metrics)
    $delta = $m1 - $m0
    if ($delta -gt 1) { $v1Note = "单次网关请求 broker 计数 delta=$delta（>1 提示存在额外上游探测）" }
    elseif ($delta -eq 1) { $v1Note = "单次网关请求 broker 计数 delta=1（未观察到额外上游探测）" }
    else { $v1Note = "delta=$delta（请求未达 broker？核对 F1）" }
    Write-Host "  [V1c] $v1Note" -ForegroundColor DarkCyan

    # ---------- G. 白名单/未知 provider 404 + request_id ----------
    Write-Host "`n[G] 白名单/未知 provider（broker 直连 $BrokerBase）" -ForegroundColor Yellow
    $hdrFile = Join-Path $tmpDir 'g1-headers.txt'
    $g1body = Join-Path $tmpDir 'g1-body.txt'
    $g1 = & curl.exe -s -m 10 -D $hdrFile -o $g1body -w '%{http_code}' "$BrokerBase/llm-broker/$BrokerRouteKey/v1/healthzz" 2>$null
    Check 'G1 路径白名单外 404（path_denied）' ("$g1".Trim() -eq '404') "(code=$("$g1".Trim()))"
    $g2 = & curl.exe -s -m 10 -o (Join-Path $tmpDir 'g2-body.txt') -w '%{http_code}' "$BrokerBase/llm-broker/unknown-provider/v1/models" 2>$null
    Check 'G2 未知 provider 404（provider_unknown）' ("$g2".Trim() -eq '404') "(code=$("$g2".Trim()))"
    $hdrText = if (Test-Path $hdrFile) { [System.IO.File]::ReadAllText($hdrFile) } else { '' }
    Check 'G3 404 响应含 X-Request-ID（S-3 request_id 关联）' ($hdrText -match '(?im)^X-Request-ID:\s*\S+')

    $g4 = & curl.exe -s -m 15 -o (Join-Path $tmpDir 'g4-body.json') -w '%{http_code}' "$BrokerBase/llm-broker/$BrokerRouteKey/v1/models" 2>$null
    Write-Host "  [V1a] GET /v1/models 经 broker → 上游 HTTP $("$g4".Trim())" -ForegroundColor DarkCyan
    Write-JsonFile (Join-Path $tmpDir 'g5-req.json') @{ model = $cmaasModel; input = 'hi' }
    $g5 = & curl.exe -s -m 30 -o (Join-Path $tmpDir 'g5-body.json') -w '%{http_code}' -X POST "$BrokerBase/llm-broker/$BrokerRouteKey/v1/embeddings" `
        -H 'Content-Type: application/json' --data-binary "@$(Join-Path $tmpDir 'g5-req.json')" 2>$null
    Write-Host "  [V1b] POST /v1/embeddings 经 broker → 上游 HTTP $("$g5".Trim())" -ForegroundColor DarkCyan
    $v1Note = "models=$("$g4".Trim()), embeddings=$("$g5".Trim())；$v1Note"

    # ---------- H. 指标汇总 ----------
    Write-Host "`n[H] 指标汇总（gateway_admin_broker_requests_total）" -ForegroundColor Yellow
    (Get-Metrics) -split "`n" | Where-Object { $_ -match '^gateway_admin_broker_requests_total' } | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }

    # ================= I. M2 A-1：凭据托管链路（直连 Go 服务） =================
    Write-Host "`n[I] M2 A-1 凭据托管链路（/v1/adminext/broker-providers）" -ForegroundColor Yellow
    $probe = 'pilot-a1'
    $probeBase = "$BrokerBase/v1/adminext/broker-providers"

    # I1 写入受理 + customUrl
    $body = @{ upstream = $cmaasUrl; key = $apiKey }
    $r1 = Invoke-BrokerApi 'POST' "$probeBase/$probe" $body $AdminUser 'admin'
    $wantUrl = "$brokerPublicBase/llm-broker/$probe/v1/chat/completions"
    $i1ok = ($r1.Code -eq 200)
    if (-not $i1ok) {
        # broker 未启用以外的失败（如 403/400）如实报出
        Check 'I1 admin 写入凭据受理（200）' $false "(code=$($r1.Code)) $($r1.Body)"
    } else {
        $res1 = $null; try { $res1 = $r1.Body | ConvertFrom-Json } catch {}
        $i1ok = ($res1 -and $res1.customUrl -eq $wantUrl)
        Check 'I1 admin 写入凭据受理 + customUrl 正确' $i1ok "(code=200, customUrl=$(if($res1){$res1.customUrl}else{'解析失败'}))"
    }

    # I2 响应不回显 Key（前提 I1 成功：否则空响应会误判为"无 Key"）
    Check 'I2 写入响应不回显 Key' ($i1ok -and ($r1.Body.IndexOf($apiKey) -lt 0)) "(resp_len=$($r1.Body.Length))"

    # I3 凭据文件原子落盘（无 .tmp 残留）
    $credFile = Join-Path $secretsDir "$probe.env"
    $tmpLeft = Test-Path ($credFile + '.tmp')
    Check 'I3 凭据文件已落盘且无 .tmp 残留' ((Test-Path $credFile) -and (-not $tmpLeft)) "(file=$probe.env)"

    # I4 热加载即时生效：新 provider 进入路由表（以 path_denied 指标证明，不触上游）
    & curl.exe -s -m 10 -o (Join-Path $tmpDir 'i4-body.txt') -w '%{http_code}' "$BrokerBase/llm-broker/$probe/v1/__probe" 2>$null | Out-Null
    $mAfter = Get-Metrics
    Check 'I4 热加载即时生效（新 provider 进入路由表）' ($mAfter -match ('provider="' + $probe + '",code="404",reason="path_denied"')) '(无需重启，路由表原子切换)'

    # I5 列表：含 pilot-a1 且无 Key
    $r5 = Invoke-BrokerApi 'GET' $probeBase $null $AdminUser 'admin'
    $hasProbe = ($r5.Body -match ('"name"\s*:\s*"' + $probe + '"'))
    Check 'I5 列表含新 provider 且不回显 Key' (($r5.Code -eq 200) -and $hasProbe -and ($r5.Body.IndexOf($apiKey) -lt 0)) "(code=$($r5.Code))"

    # I6 详情：含指纹，不含 Key
    $r6 = Invoke-BrokerApi 'GET' "$probeBase/$probe" $null $AdminUser 'admin'
    $fp = ''
    $fpWant = ''
    if ($r6.Code -eq 200) {
        $v6 = $null; try { $v6 = $r6.Body | ConvertFrom-Json } catch {}
        if ($v6) { $fp = "$($v6.keyFingerprint)" }
    }
    $sha = [System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($apiKey))
    $fpWant = (($sha[0..3] | ForEach-Object { $_.ToString('x2') }) -join '')
    Check 'I6 详情含 Key 指纹且与算法一致、不含 Key' (($r6.Code -eq 200) -and ($fp -eq $fpWant) -and ($r6.Body.IndexOf($apiKey) -lt 0)) "(fingerprint=$fp)"

    # I7 参数校验
    $r7a = Invoke-BrokerApi 'POST' "$probeBase/bad-http" @{ upstream = 'http://example.com'; key = $apiKey } $AdminUser 'admin'
    $r7b = Invoke-BrokerApi 'POST' "$probeBase/BadName" @{ upstream = $cmaasUrl; key = $apiKey } $AdminUser 'admin'
    $r7c = Invoke-BrokerApi 'POST' "$probeBase/short-key" @{ upstream = $cmaasUrl; key = 'short' } $AdminUser 'admin'
    Check 'I7 参数校验（http 上游 / 名非法 / key 过短 → 400）' (($r7a.Code -eq 400) -and ($r7b.Code -eq 400) -and ($r7c.Code -eq 400)) "(code=$($r7a.Code)/$($r7b.Code)/$($r7c.Code))"

    # I8 最小角色控制：auditor 写 403 / auditor 读 200 / admin 写 200
    $r8a = Invoke-BrokerApi 'POST' "$probeBase/auditor-try" @{ upstream = $cmaasUrl; key = $apiKey } $AuditorUser 'auditor'
    $r8b = Invoke-BrokerApi 'GET' $probeBase $null $AuditorUser 'auditor'
    # 关键：令牌自称 admin 但 sub 不在白名单 → 仍须 403（不采信 JWT role）
    $r8c = Invoke-BrokerApi 'POST' "$probeBase/auditor-try" @{ upstream = $cmaasUrl; key = $apiKey } $AuditorUser 'admin'
    Check 'I8 auditor 写 403' ($r8a.Code -eq 403) "(code=$($r8a.Code))"
    Check 'I8 auditor 读 200' ($r8b.Code -eq 200) "(code=$($r8b.Code))"
    Check 'I8 伪造 admin 声明的非白名单用户仍 403（不采信 JWT role）' ($r8c.Code -eq 403) "(code=$($r8c.Code))"
    Check 'I8 越权写入无副作用（未落盘）' (-not (Test-Path (Join-Path $secretsDir 'auditor-try.env')))

    # I9 删除 + 联动告警 + 路由即时摘除
    $r9 = Invoke-BrokerApi 'DELETE' "$probeBase/$probe" $null $AdminUser 'admin'
    $warnOk = $false
    if ($r9.Code -eq 200) {
        $v9 = $null; try { $v9 = $r9.Body | ConvertFrom-Json } catch {}
        if ($v9 -and $v9.warning) { $warnOk = $true }
    }
    Check 'I9 删除受理且返回 CR 联动告警' (($r9.Code -eq 200) -and $warnOk) "(code=$($r9.Code))"
    $r9b = Invoke-BrokerApi 'GET' $probeBase $null $AdminUser 'admin'
    Check 'I9 删除后列表不再含该 provider' (($r9b.Code -eq 200) -and ($r9b.Body -notmatch ('"name"\s*:\s*"' + $probe + '"')))
    $r9c = Invoke-BrokerApi 'DELETE' "$probeBase/$probe" $null $AdminUser 'admin'
    Check 'I9 重复删除 404（幂等语义）' ($r9c.Code -eq 404) "(code=$($r9c.Code))"

    # I10 漂移检测：删主凭据 → orphanDetected；恢复 → 消除
    $r10a = Invoke-BrokerApi 'DELETE' "$probeBase/$BrokerRouteKey" $null $AdminUser 'admin'
    $r10b = Invoke-BrokerApi 'GET' $probeBase $null $AdminUser 'admin'
    $orphanHit = ($r10b.Body -match 'orphanDetected') -and ($r10b.Body -match $BrokerRouteKey)
    Check 'I10 删除凭据后列表报漂移（orphanDetected）' (($r10a.Code -eq 200) -and $orphanHit) "(code=$($r10a.Code))"

    $r10c = Invoke-BrokerApi 'POST' "$probeBase/$BrokerRouteKey" @{ upstream = $cmaasUrl; key = $apiKey } $AdminUser 'admin'
    $r10d = Invoke-BrokerApi 'GET' $probeBase $null $AdminUser 'admin'
    $orphanGone = ($r10d.Body -notmatch 'orphanDetected')
    Check 'I10 恢复凭据后漂移消除' (($r10c.Code -eq 200) -and $orphanGone) "(code=$($r10c.Code))"
    $g10 = & curl.exe -s -m 15 -o (Join-Path $tmpDir 'i10-body.json') -w '%{http_code}' "$BrokerBase/llm-broker/$BrokerRouteKey/v1/models" 2>$null
    Check 'I10 恢复后主链路可用（/v1/models 经 broker）' ("$g10".Trim() -eq '200') "(上游 code=$("$g10".Trim()))"

    # I11 console→Go 转发目标配置状态（信息项；未配置则 UI 链路需按手册 §7.1 启动控制台）
    $target = docker exec $Container printenv ADMIN_SVC_TARGET 2>$null
    if ($target) {
        Write-Host "  [I11] console ADMIN_SVC_TARGET=$target（UI 链路已配置转发目标）" -ForegroundColor DarkCyan
    } else {
        Warn 'I11 console→Go 转发目标未配置' "容器内 ADMIN_SVC_TARGET 为空 → admin-ext 页面链路未启用（需按 docs/管理门户-升级操作手册.md §7.1 以 ADMIN_SVC_TARGET/ADMIN_SVC_JWT_SECRET 启动控制台，并用同一 JWT 密钥启动本服务）"
    }
}   # if ($brokerReady)
}
finally {
    # 清理：容器内临时文件 + 宿主临时目录；
    # 若 broker 为本脚本启动（$svcProc 非空且仍在运行），先停止再删 exe（否则文件被锁定无法删除）。
    docker exec $Container sh -c "rm -f ${ctrTmp}-req.json ${ctrTmp}-resp.json ${ctrTmp}.cookies" 2>$null | Out-Null
    if ($null -ne $svcProc -and -not $svcProc.HasExited) {
        try { Stop-Process -Id $svcProc.Id -Force -ErrorAction Stop } catch {}
        Start-Sleep -Milliseconds 500
    }
    if (Test-Path $tmpDir) {
        try { Remove-Item -Recurse -Force $tmpDir -ErrorAction Stop }
        catch { Write-Host ("[WARN] 临时目录清理失败：" + $_.Exception.Message) -ForegroundColor Yellow }
    }
}

# ---------- 汇总 ----------
Write-Host "`n===== 汇总 =====" -ForegroundColor Cyan
$pass = ($results | Where-Object { $_.Status -eq 'PASS' }).Count
$warn = ($results | Where-Object { $_.Status -eq 'WARN' }).Count
$fail = ($results | Where-Object { $_.Status -eq 'FAIL' }).Count
Write-Host "PASS=$pass  WARN=$warn  FAIL=$fail" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
$results | Where-Object { $_.Status -ne 'PASS' } | ForEach-Object { Write-Host ("  " + $_.Status + " " + $_.Name + ' - ' + $_.Detail) -ForegroundColor $(if ($_.Status -eq 'FAIL') { 'Red' } else { 'Yellow' }) }
Write-Host "`n验证点观察（回填 docs/管理门户-apiTokens-Secret化方案设计.md §9）：" -ForegroundColor Cyan
Write-Host "  V1（customUrl 多路径语义）：$v1Note"
Write-Host "  V2（API 空 tokens 校验）：$v2Note"
if ($fail -gt 0) { exit 1 }
exit 0
