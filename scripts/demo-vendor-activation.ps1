# demo-vendor-activation.ps1 - 展示环境2.0 · 厂商激活演示（真实 Phala 链路，M1 WP-D 配套）
#
# 自动化验证场景并打印 PASS/FAIL：
#   A. 预检               容器/网关端口就绪；cmaas.env 密钥配置可读；fork 控制台(:18001)登录会话可用
#   B. 厂商激活           经控制台 API 激活 provider（type=openai + openaiCustomUrl 指向 Phala，
#                         key 由 cmaas.env 内存注入 → 临时 JSON 文件 --data-binary 直传，
#                         不入命令行/进程列表/日志）；GET 核验条目在位
#   C. AI 路由            建路由 /phala → provider phala（控制台自动生成 ServiceSource/受管 ai-proxy 配置）
#   D. 明文直连推理       POST :8080/phala/v1/chat/completions（ai-proxy 注入 key 直连 Phala，
#                         不经 otpmask 密态段；密态链路另见 demo-phala-chain.ps1）→ 200 非空回复
#   E. 掩码语义核验       GET provider 的 tokens 与真实 key 后 4 位一致（WP-D 厂商页 maskToken
#                         仅展示后 4 位的数据源语义）；/admin-ext/vendors.html 页面资源可达
#
# 边界（如实）：当前控制台 Provider API 把 key 明文存入受管 ai-proxy 配置（standalone 本机演示
# 环境可接受）；"加密落 Secret + 界面不回显"目标态属 M2（docs/管理门户-细化方案.md §5.1/§6）。
#
# 前置：higress-standalone 容器运行中；容器内 fork console jar 运行于 :18001（env 见
#       docs/管理门户-升级操作手册.md §7.1）；deploy/secrets/cmaas.env 已配置。
# 用法：powershell -ExecutionPolicy Bypass -File scripts\demo-vendor-activation.ps1
# 退出码：0 = 全部通过；1 = 存在失败（可接 CI）。
#
# 注：本脚本为 UTF-8 with BOM；含中文，勿改为无 BOM 保存（PS 5.1 按 ANSI 解析会坏语法）。

param(
    [string]$Container = 'higress-chain-control-plane',
    [int]$ConsolePort = 18001,
    [string]$Gateway = 'http://127.0.0.1:8080',
    [string]$ProviderName = 'phala',
    [string]$RouteName = 'phala-demo',
    [string]$RoutePath = '/phala',
    [string]$User = 'adminExtSmoke',
    [string]$Pass = 'Adm1n-Smoke-2026',
    [switch]$SkipPreflight
)

$ErrorActionPreference = 'Stop'

$results = @()
function Check([string]$name, [bool]$ok, [string]$detail = '') {
    $tag = if ($ok) { 'PASS' } else { 'FAIL' }
    $script:results += [pscustomobject]@{ Name = $name; Status = $tag; Detail = $detail }
    if ($ok) { Write-Host "[$tag] $name $detail" -ForegroundColor Green }
    else { Write-Host "[$tag] $name $detail" -ForegroundColor Red }
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
    # -Encoding UTF8：防 PS 5.1 ANSI 误码吞行丢密钥（同 start-tee-infer-phala.ps1）
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

# ---------- 临时目录（请求体经文件直传，规避 PS 内联引号/密钥入命令行） ----------
$tmpDir = Join-Path $env:TEMP 'vendor-activation-demo'
if (Test-Path $tmpDir) { Remove-Item -Recurse -Force $tmpDir }
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$ctrTmp = '/tmp/adminext-demo'

function Write-JsonFile([string]$file, [object]$obj) {
    [System.IO.File]::WriteAllText($file, ($obj | ConvertTo-Json -Depth 8 -Compress), (New-Object System.Text.UTF8Encoding($false)))
}

# 容器内 console API 调用：body/响应经 docker cp 文件直传（容器内 sh -c 无内嵌双引号）
# 返回 @{ Code = http_code; Body = 响应 JSON 文本 }；Body 不回显（含明文 token 可能）。
function Invoke-ConsoleApi([string]$method, [string]$path, [object]$body) {
    $reqHost = Join-Path $tmpDir 'req.json'
    if ($null -ne $body) { Write-JsonFile $reqHost $body }
    if ($null -ne $body) { docker cp $reqHost "${Container}:${ctrTmp}-req.json" 2>$null | Out-Null }

    $dataArg = ''
    if ($null -ne $body) { $dataArg = "--data-binary @${ctrTmp}-req.json" }
    $cmd = "curl -s -m 60 -X $method -H Content-Type:application/json -b ${ctrTmp}.cookies -c ${ctrTmp}.cookies $dataArg -o ${ctrTmp}-resp.json -w `%{http_code} http://127.0.0.1:${ConsolePort}$path"
    $code = docker exec $Container sh -c $cmd 2>$null
    $respHost = Join-Path $tmpDir 'resp.json'
    docker cp "${Container}:${ctrTmp}-resp.json" $respHost 2>$null | Out-Null
    $bodyText = ''
    if (Test-Path $respHost) { $bodyText = [System.IO.File]::ReadAllText($respHost) }
    return [pscustomobject]@{ Code = "$code".Trim(); Body = $bodyText }
}

function Upsert-Json([string]$api, [string]$resourceName, [object]$body) {
    # POST 为主；409/500（同名已存在，控制台对重复创建的映射不一致）→ PUT 幂等覆盖
    $r = Invoke-ConsoleApi 'POST' $api $body
    if ($r.Code -eq '409' -or $r.Code -eq '500') {
        $r = Invoke-ConsoleApi 'PUT' "$api/$resourceName" $body
    }
    return $r
}

Write-Host '===== 展示环境2.0 · 厂商激活演示（真实 Phala 链路） =====' -ForegroundColor Cyan
Write-Host "Container=$Container ConsolePort=$ConsolePort Gateway=$Gateway Provider=$ProviderName"
$failCount = 0

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

    # ---------- B. 厂商激活 ----------
    Write-Host "`n[B] 厂商激活（控制台 API，openai 兼容 + openaiCustomUrl）" -ForegroundColor Yellow
    $providerBody = @{
        name     = $ProviderName
        type     = 'openai'
        protocol = 'openai/v1'
        tokens   = @($apiKey)
        rawConfigs = @{ openaiCustomUrl = "$cmaasUrl/v1/chat/completions" }
    }
    $r = Upsert-Json '/v1/ai/providers' $ProviderName $providerBody
    Check 'B1 激活请求受理' ($r.Code -eq '200' -or $r.Code -eq '201') "(code=$($r.Code))"
    $r = Invoke-ConsoleApi 'GET' "/v1/ai/providers/$ProviderName" $null
    Check 'B2 provider 条目在位' ($r.Code -eq '200' -and $r.Body -match ('"name"\s*:\s*"' + $ProviderName + '"')) "(code=$($r.Code))"

    # ---------- C. AI 路由 ----------
    Write-Host "`n[C] AI 路由（$RoutePath → provider $ProviderName）" -ForegroundColor Yellow
    $routeBody = @{
        name          = $RouteName
        pathPredicate = @{ matchType = 'PRE'; matchValue = $RoutePath }
        upstreams     = @(@{ provider = $ProviderName; weight = 100 })
    }
    $r = Upsert-Json '/v1/ai/routes' $RouteName $routeBody
    Check 'C1 路由创建受理' ($r.Code -eq '200' -or $r.Code -eq '201') "(code=$($r.Code))"
    $r = Invoke-ConsoleApi 'GET' "/v1/ai/routes/$RouteName" $null
    Check 'C2 路由条目在位' ($r.Code -eq '200' -and $r.Body -match ('"name"\s*:\s*"' + $RouteName + '"')) "(code=$($r.Code))"

    # ---------- D. 明文直连推理 ----------
    Write-Host "`n[D] 明文直连推理（ai-proxy 注入 key → Phala，不经 otpmask 密态段）" -ForegroundColor Yellow
    Start-Sleep -Seconds 3   # Envoy 配置传播窗口
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
        Start-Sleep -Seconds 5   # 路由/上游（DNS registry）就绪窗口
    }
    Check 'D1 直连推理 HTTP 200' ("$code".Trim() -eq '200') "(code=$("$code".Trim()))"
    if ("$code".Trim() -eq '200' -and (Test-Path $inferFile)) {
        try {
            $j = [System.IO.File]::ReadAllText($inferFile) | ConvertFrom-Json
            $content = $j.choices[0].message.content
        } catch { $content = '' }
    }
    Check 'D2 回复明文非空' ($content -ne '')
    if ($content) { Write-Host ("    Phala 回复: " + $content.Substring(0, [Math]::Min(80, $content.Length))) -ForegroundColor DarkCyan }

    # ---------- E. 掩码语义核验 ----------
    Write-Host "`n[E] 掩码语义核验（WP-D 厂商页数据源）" -ForegroundColor Yellow
    $r = Invoke-ConsoleApi 'GET' "/v1/ai/providers/$ProviderName" $null
    $last4 = if ($apiKey.Length -ge 4) { $apiKey.Substring($apiKey.Length - 4) } else { '' }
    Check 'E1 tokens 含真实 key（后 4 位一致，页面 maskToken 仅示后 4 位）' `
        ($r.Code -eq '200' -and $last4 -and $r.Body -match $last4)
    $pageCode = docker exec $Container sh -c "curl -s -m 10 -o /dev/null -w %{http_code} http://127.0.0.1:${ConsolePort}/admin-ext/vendors.html" 2>$null
    Check 'E2 WP-D 厂商状态页资源可达（/admin-ext/vendors.html）' ("$pageCode".Trim() -eq '200') "(code=$("$pageCode".Trim()))"
}
finally {
    # 清理：容器内临时请求体（含密钥）与宿主临时目录一并删除
    docker exec $Container sh -c "rm -f ${ctrTmp}-req.json ${ctrTmp}-resp.json ${ctrTmp}.cookies" 2>$null | Out-Null
    if (Test-Path $tmpDir) { Remove-Item -Recurse -Force $tmpDir }
}

# ---------- 汇总 ----------
Write-Host "`n===== 汇总 =====" -ForegroundColor Cyan
$pass = ($results | Where-Object { $_.Status -eq 'PASS' }).Count
$fail = ($results | Where-Object { $_.Status -eq 'FAIL' }).Count
Write-Host "PASS=$pass  FAIL=$fail" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
$results | Where-Object { $_.Status -eq 'FAIL' } | ForEach-Object { Write-Host ("  FAIL " + $_.Name + ' - ' + $_.Detail) -ForegroundColor Red }
if ($fail -gt 0) { exit 1 }
exit 0
