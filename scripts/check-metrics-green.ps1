# check-metrics-green.ps1 - 指标"全绿"可执行判定（Phase 1 门禁 #9）
#
# 定位：把 GA 总览 §6 门禁 #9 的"Prometheus 指标全绿"从**人工判断**变成**可执行门禁**。
#
# 判定语义（如实，不做静默降级）：
#   清单三列：<source> <metric> <required|conditional>
#   - 来源不可达                          → SKIP（不计失败，提示如何拉起）
#   - required 指标缺失（来源可达）        → FAIL（"全绿"未达成）
#   - conditional 指标缺失                → SKIP（条件注册：其触发事件/开关未发生，非缺陷）
#
# 为什么区分 required/conditional：插件计数器为 proxywasm 懒注册（首次 incr 才 Define），
# tee-infer 亦然——"从未触发过的计数器不存在"是设计内行为，若一律判 FAIL 则"全绿"永不可达。
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File scripts\check-metrics-green.ps1
#   ... -Tee http://127.0.0.1:19090 -TeeToken <token> -Admin http://127.0.0.1:19095 `
#       -Core http://127.0.0.1:8085 -CoreToken <OTP_CORE_AUTH_TOKEN> `
#       -Container higress-chain-control-plane       # 数据面 stats 经容器内 :15000
#   来源：tee | admin | core | plugin；跳过来源：-SkipTee / -SkipAdmin / -SkipCore / -SkipPlugin
#
# 退出码：0 = required 全命中（conditional 可 SKIP）；1 = 存在 FAIL；2 = 脚本自身错误
#
# 注：本脚本为 UTF-8 with BOM（含中文；PS 5.1 按 ANSI 解析会坏语法）。

param(
    [string]$Tee = 'http://127.0.0.1:19090',
    [string]$TeeToken = '',
    [string]$Admin = 'http://127.0.0.1:19095',
    [string]$Core = 'http://127.0.0.1:8085',
    [string]$CoreToken = '',
    [string]$Cryptop = 'http://127.0.0.1:19097',
    [string]$Container = 'higress-chain-control-plane',
    [string]$Manifest = '',
    [int]$TimeoutSec = 15,
    [switch]$SkipTee,
    [switch]$SkipAdmin,
    [switch]$SkipCore,
    [switch]$SkipPlugin,
    [switch]$SkipCryptop,
    # 门禁模式（verify-all 用）：全部来源必须可达，任一个不可达即 FAIL（避免"空跑通过"）
    [switch]$RequireAllSources
)

$ErrorActionPreference = 'Stop'
if (-not $Manifest) { $Manifest = Join-Path $PSScriptRoot 'metrics-required.txt' }
if (-not (Test-Path $Manifest)) { Write-Host "清单不存在: $Manifest" -ForegroundColor Red; exit 2 }

$results = New-Object System.Collections.ArrayList
function Record([string]$source, [string]$metric, [string]$kind, [string]$status, [string]$detail) {
    [void]$results.Add([pscustomobject]@{ Source = $source; Metric = $metric; Kind = $kind; Status = $status; Detail = $detail })
}

function Get-HttpBody([string]$url, [string[]]$headers) {
    try {
        $req = [System.Net.HttpWebRequest]::Create($url)
        $req.Method = 'GET'
        $req.Timeout = $TimeoutSec * 1000
        foreach ($h in $headers) { $k, $v = $h -split ':', 2; $req.Headers.Add($k.Trim(), $v.Trim()) }
        $resp = $req.GetResponse()
        $rd = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
        $t = $rd.ReadToEnd(); $rd.Close(); $resp.Close()
        return @{ ok = $true; body = $t }
    } catch {
        return @{ ok = $false; body = $_.Exception.Message }
    }
}

# ---------- 抓取三个来源 ----------
Write-Host '===== 指标全绿判定（门禁 #9）=====' -ForegroundColor Cyan

$teeBody = ''; $teeUp = $false
if (-not $SkipTee) {
    $h = @(); if ($TeeToken) { $h = @("X-Admin-Token: $TeeToken") }
    $r = Get-HttpBody "$Tee/metrics" $h
    $teeUp = $r.ok
    if ($teeUp) { $teeBody = $r.body } else { Write-Host "  [SKIP] tee-infer 不可达（$Tee/metrics）：$($r.body)" -ForegroundColor DarkYellow }
} else { Write-Host '  [SKIP] 按参数跳过 tee-infer' -ForegroundColor DarkYellow }

$adminBody = ''; $adminUp = $false
if (-not $SkipAdmin) {
    $r = Get-HttpBody "$Admin/metrics" @()
    $adminUp = $r.ok
    if ($adminUp) { $adminBody = $r.body } else { Write-Host "  [SKIP] 管理面不可达（$Admin/metrics）：$($r.body)" -ForegroundColor DarkYellow }
} else { Write-Host '  [SKIP] 按参数跳过管理面' -ForegroundColor DarkYellow }

$coreBody = ''; $coreUp = $false
if (-not $SkipCore) {
    $h = @(); if ($CoreToken) { $h = @("Authorization: Bearer $CoreToken") }
    $r = Get-HttpBody "$Core/metrics" $h
    $coreUp = $r.ok
    if ($coreUp) { $coreBody = $r.body } else { Write-Host "  [SKIP] 控制面不可达（$Core/metrics）：$($r.body)" -ForegroundColor DarkYellow }
} else { Write-Host '  [SKIP] 按参数跳过控制面' -ForegroundColor DarkYellow }

$pluginBody = ''; $pluginUp = $false
if (-not $SkipPlugin) {
    try {
        $out = & docker exec $Container sh -c "curl -s -m $TimeoutSec http://127.0.0.1:15000/stats" 2>$null
        if ($LASTEXITCODE -eq 0 -and "$out".Trim()) { $pluginUp = $true; $pluginBody = "$out" }
    } catch { }
    if (-not $pluginUp) { Write-Host "  [SKIP] 数据面 stats 不可达（容器 $Container :15000）" -ForegroundColor DarkYellow }
} else { Write-Host '  [SKIP] 按参数跳过数据面插件' -ForegroundColor DarkYellow }

$cryptopBody = ''; $cryptopUp = $false
if (-not $SkipCryptop) {
    $r = Get-HttpBody "$Cryptop/metrics" @()
    $cryptopUp = $r.ok
    if ($cryptopUp) { $cryptopBody = $r.body } else { Write-Host "  [SKIP] cryptop sidecar 不可达（$Cryptop/metrics）：$($r.body)" -ForegroundColor DarkYellow }
} else { Write-Host '  [SKIP] 按参数跳过 cryptop sidecar' -ForegroundColor DarkYellow }

# ---------- 逐条断言 ----------
foreach ($line in [System.IO.File]::ReadAllLines($Manifest)) {
    $t = $line.Trim()
    if (-not $t -or $t.StartsWith('#')) { continue }
    $parts = $t -split '\s+'
    if ($parts.Count -lt 2) { Record 'manifest' $t 'required' 'FAIL' '清单格式非法（应为 <source> <metric> [required|conditional]）'; continue }
    $src = $parts[0]; $metric = $parts[1]
    $kind = if ($parts.Count -ge 3) { $parts[2] } else { 'required' }

    $body = ''; $up = $false; $srcName = ''
    switch ($src) {
        'tee'    { $body = $teeBody;    $up = $teeUp;    $srcName = 'tee-infer /metrics' }
        'admin'  { $body = $adminBody;  $up = $adminUp;  $srcName = '管理面 /metrics' }
        'core'   { $body = $coreBody;   $up = $coreUp;   $srcName = '控制面 /metrics' }
        'plugin' { $body = $pluginBody; $up = $pluginUp; $srcName = '数据面 Envoy stats' }
        'cryptop' { $body = $cryptopBody; $up = $cryptopUp; $srcName = 'cryptop sidecar /metrics' }
        default  { Record $src $metric $kind 'FAIL' "未知来源: $src"; continue }
    }

    if (-not $up) {
        if ($RequireAllSources) { Record $src $metric $kind 'FAIL' "$srcName 不可达（门禁模式要求全部来源可达）" }
        else { Record $src $metric $kind 'SKIP' "$srcName 不可达" }
        continue
    }
    if ($body -match [regex]::Escape($metric)) { Record $src $metric $kind 'PASS' ''; continue }
    if ($kind -eq 'conditional') { Record $src $metric $kind 'SKIP' '条件指标未触发（设计内：懒注册，其事件/开关未发生）'; continue }
    Record $src $metric $kind 'FAIL' "$srcName 缺失且为 required"
}

# ---------- 汇总 ----------
$pass = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
$fail = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
$skip = @($results | Where-Object { $_.Status -eq 'SKIP' }).Count
$reqFail = @($results | Where-Object { $_.Status -eq 'FAIL' -and $_.Kind -eq 'required' }).Count

foreach ($r in ($results | Where-Object { $_.Status -ne 'PASS' })) {
    $color = if ($r.Status -eq 'FAIL') { 'Red' } else { 'DarkYellow' }
    Write-Host ("[{0}] {1} {2} ({3}) {4}" -f $r.Status, $r.Source, $r.Metric, $r.Kind, $r.Detail) -ForegroundColor $color
}

Write-Host "`n===== 汇总 =====" -ForegroundColor Cyan
Write-Host "PASS=$pass FAIL=$fail SKIP=$skip（清单 $($results.Count) 条；required 失败 $reqFail）" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($skip -gt 0) {
    Write-Host '说明（如实）：SKIP 分两类——来源不可达 / conditional 未触发；两类都不等于"全绿"' -ForegroundColor DarkYellow
    Write-Host '      宣布"全绿"口径 = 全部来源可达 且 required 全命中（本脚本退出码 0 且 SKIP 中无"来源不可达"）' -ForegroundColor DarkYellow
}
if ($fail -gt 0) { exit 1 }
exit 0
