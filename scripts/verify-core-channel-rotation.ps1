# verify-core-channel-rotation.ps1 — 门禁 #7 边界 C：通道令牌轮换"不停机"验证
#
# 场景：运维轮换 gateway-core 拉取通道令牌（须两处同步：gateway-core 的
# OTP_CORE_AUTH_TOKEN 与 deploy/secrets/gateway-core-token.env）。插件 CR 内**不含**任何
# 通道令牌（只含 core-channel 的受限读令牌），故轮换**无需改 CR、无需重启数据面**。
# 本脚本在轮换窗口内/后采集数据面证据并断言。
#
# 断言：
#   [1] 数据面配置无明文：config_dump 中 gateway_core_token 为空、
#       gateway_core_credential_name=core-channel、被检明文令牌 0 次出现
#   [2] 端点契约：core-channel 正确读令牌 200 / 错误令牌 401 / 非 GET 405 / 未知集合 404
#   [3] 轮换窗口：限流表拉取 cb 净增 > 0（拉取未中断）、reject 增量 <= MaxRejectDelta（轮换瞬态）、
#       凭据通道 ok 净增 > 0（插件已取到新令牌）
#   [4] 可选 -BumpPolicy：控制面限流表版本 +1 → otpmask_ratelimit_fetch_ok 净增 > 0
#       （ok 语义＝"版本递增并入缓存"；同版本 tick 不计数，故默认不断言 ok）
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File scripts\verify-core-channel-rotation.ps1 `
#     -CredentialToken <core-channel 读令牌> -PlaintextToken <被检明文令牌> -SampleSeconds 90
#   （-BumpPolicy 需同时给 -CoreToken；会向控制面 PUT 一版限流表，属可观测副作用）
#
# 退出码：0 全 PASS；1 有 FAIL；2 参数/环境错误
#
# 注：本脚本为 UTF-8 with BOM（含中文；PS 5.1 按 ANSI 解析会坏语法）。

param(
    [string]$Container = 'higress-chain-control-plane',
    [string]$Admin = 'http://127.0.0.1:19097',
    [Parameter(Mandatory = $true)][string]$CredentialToken,
    [string]$PlaintextToken = '',
    [int]$SampleSeconds = 90,
    [int]$IntervalSeconds = 3,
    [int]$MaxRejectDelta = 2,
    [string]$Core = 'http://127.0.0.1:8085',
    [string]$CoreToken = '',
    [switch]$BumpPolicy
)

$ErrorActionPreference = 'Stop'
$script:failed = 0

function Check([string]$name, [bool]$ok, [string]$detail = '') {
    $tag = if ($ok) { 'PASS' } else { 'FAIL' }
    if (-not $ok) { $script:failed++ }
    $color = if ($ok) { 'Green' } else { 'Red' }
    Write-Host ("  [{0}] {1} {2}" -f $tag, $name, $detail) -ForegroundColor $color
}

# Get-Http 发起请求并返回状态码 + body（不抛异常，供契约断言用）。
function Get-Http([string]$url, [string]$token, [string]$method = 'GET') {
    $req = [System.Net.HttpWebRequest]::Create($url)
    $req.Method = $method
    $req.Timeout = 15000
    if ($token) { $req.Headers.Add('X-Credential-Token', $token) }
    try {
        $resp = $req.GetResponse()
        $code = [int]$resp.StatusCode
        $rd = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
        $body = $rd.ReadToEnd(); $rd.Close(); $resp.Close()
        return @{ code = $code; body = $body }
    } catch [System.Net.WebException] {
        $r = $_.Exception.Response
        if ($r) { return @{ code = [int]$r.StatusCode; body = '' } }
        return @{ code = -1; body = $_.Exception.Message }
    }
}

# Get-Stat 读数据面 stats 计数（多 worker 由 Envoy 按累加聚合，断言只看增量）。
function Get-Stat([string]$name) {
    $out = & docker exec $Container sh -c "curl -s http://127.0.0.1:15000/stats | grep wasmcustom.$name" 2>$null
    if ($out -match ":\s*(\d+)") { return [int]$Matches[1] }
    return -1
}

# Get-Dump 读数据面运行时配置（ECDS 内含插件 JSON 原文）。
function Get-Dump() {
    $out = & docker exec $Container sh -c "curl -s http://127.0.0.1:15000/config_dump" 2>$null | Out-String
    return $out
}

Write-Host "== 门禁 #7 边界 C：通道令牌轮换验证 ==" -ForegroundColor Cyan

# [1] 数据面配置无明文
Write-Host "[1] 数据面配置（config_dump）无明文通道令牌" -ForegroundColor Yellow
$dump = Get-Dump
if ($dump.Length -lt 1000) {
    Write-Host "  [FAIL] config_dump 不可读（容器 $Container 是否在跑？）" -ForegroundColor Red
    $script:failed++
} else {
    Check 'gateway_core_credential_name=core-channel' ($dump -match 'gateway_core_credential_name\\":\\"core-channel') '(凭据集已启用)'
    Check 'gateway_core_token 为空' ($dump -match 'gateway_core_token\\":\\"\\"') '(CR 内无明文通道令牌)'
    if ($PlaintextToken) {
        $n = ([regex]::Matches($dump, [regex]::Escape($PlaintextToken))).Count
        Check '被检明文令牌不出现' ($n -eq 0) ("出现次数=$n")
    } else {
        Write-Host '  [SKIP] 未给 -PlaintextToken，跳过明文出现次数断言' -ForegroundColor DarkYellow
    }
}

# [2] 端点契约
Write-Host "[2] 凭据端点契约" -ForegroundColor Yellow
$base = "$Admin/v1/adminext/credentials"
$r = Get-Http "$base/core-channel" $CredentialToken
Check 'core-channel 200（正确读令牌）' ($r.code -eq 200) ("HTTP=$($r.code)")
$served = ''
if ($r.code -eq 200) { try { $served = ($r.body | ConvertFrom-Json).token } catch { } }
Check '仅返回 token 字段' ($r.code -eq 200 -and $served -and ($r.body -notmatch 'sig_key|attest_token')) '(集合字段白名单)'
$r2 = Get-Http "$base/core-channel" '__wrong-token__'
Check '错误读令牌 401' ($r2.code -eq 401) ("HTTP=$($r2.code)")
$r3 = Get-Http "$base/core-channel" $CredentialToken 'POST'
Check '非 GET 405' ($r3.code -eq 405) ("HTTP=$($r3.code)")
$r4 = Get-Http "$base/no-such-set" $CredentialToken
Check '未知集合 404' ($r4.code -eq 404) ("HTTP=$($r4.code)")

# [3] 轮换窗口采样
Write-Host ("[3] 轮换窗口采样（{0}s，采样间隔 {1}s）" -f $SampleSeconds, $IntervalSeconds) -ForegroundColor Yellow
$cb0 = Get-Stat 'otpmask_ratelimit_fetch_cb_total'
$rj0 = Get-Stat 'otpmask_ratelimit_fetch_reject_total'
$ok0 = Get-Stat 'otpmask_core_channel_fetch_ok_total'
if ($cb0 -lt 0) {
    Write-Host '  [FAIL] 数据面计数不可读（插件未加载或 stats 关闭）' -ForegroundColor Red
    $script:failed++
} else {
    Write-Host ("  基线: ratelimit_cb=$cb0 ratelimit_reject=$rj0 core_channel_ok=$ok0") -ForegroundColor DarkGray
    $cbMax = $cb0; $rjMax = $rj0
    $deadline = (Get-Date).AddSeconds($SampleSeconds)
    $samples = 0
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $IntervalSeconds
        $samples++
        $cb = Get-Stat 'otpmask_ratelimit_fetch_cb_total'
        $rj = Get-Stat 'otpmask_ratelimit_fetch_reject_total'
        if ($cb -gt $cbMax) { $cbMax = $cb }
        if ($rj -gt $rjMax) { $rjMax = $rj }
    }
    $ok1 = Get-Stat 'otpmask_core_channel_fetch_ok_total'
    $cbDelta = $cbMax - $cb0
    $rjDelta = $rjMax - $rj0
    $okDelta = $ok1 - $ok0
    Write-Host ("  {0} 次采样后: ratelimit_cb=+{1} ratelimit_reject=+{2} core_channel_ok=+{3}" -f $samples, $cbDelta, $rjDelta, $okDelta) -ForegroundColor DarkGray
    Check '限流表拉取未中断（cb 净增>0）' ($cbDelta -gt 0) "净增=$cbDelta"
    Check ("轮换瞬态受控（reject 增量<={0}）" -f $MaxRejectDelta) ($rjDelta -le $MaxRejectDelta) "净增=$rjDelta"
    Check '插件已取到（新）通道令牌（凭据 ok 净增>0）' ($okDelta -gt 0) "净增=$okDelta"
}

# [4] 可选：版本 +1 → ok 增长（证明当前令牌端到端可用：拉取→验签→入缓存）
if ($BumpPolicy) {
    Write-Host '[4] 控制面限流表版本 +1 → 限流表 ok 增长' -ForegroundColor Yellow
    if (-not $CoreToken) {
        Write-Host '  [FAIL] -BumpPolicy 需同时给 -CoreToken' -ForegroundColor Red
        $script:failed++
    } else {
        $req = [System.Net.HttpWebRequest]::Create("$Core/ratelimits")
        $req.Method = 'GET'; $req.Timeout = 15000
        $req.Headers.Add('Authorization', "Bearer $CoreToken")
        try {
            $resp = $req.GetResponse()
            $rd = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
            $tbl = $rd.ReadToEnd(); $rd.Close(); $resp.Close()
            $obj = $tbl | ConvertFrom-Json
            $obj.version = [int]$obj.version + 1
            $obj.issued_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            if ($obj.PSObject.Properties.Name -contains 'signature') { $obj.PSObject.Properties.Remove('signature') }
            $body = $obj | ConvertTo-Json -Depth 8 -Compress
            $ok0 = Get-Stat 'otpmask_ratelimit_fetch_ok_total'
            $put = [System.Net.HttpWebRequest]::Create("$Core/ratelimits")
            $put.Method = 'PUT'; $put.Timeout = 15000
            $put.ContentType = 'application/json'
            $put.Headers.Add('Authorization', "Bearer $CoreToken")
            $put.Headers.Add('X-Actor', 'verify-core-channel-rotation')
            $put.Headers.Add('X-Request-ID', 'c4-verify-' + (Get-Date -Format 'yyyyMMddHHmmss'))
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
            $put.ContentLength = $bytes.Length
            $s = $put.GetRequestStream(); $s.Write($bytes, 0, $bytes.Length); $s.Close()
            $presp = $put.GetResponse()
            $pcode = [int]$presp.StatusCode
            $presp.Close()
            Check '控制面接受新版本表' ($pcode -eq 200) ("HTTP=$pcode version=$($obj.version)")
            $ok1 = $ok0
            $deadline = (Get-Date).AddSeconds(30)
            while ((Get-Date) -lt $deadline) {
                Start-Sleep -Seconds 3
                $ok1 = Get-Stat 'otpmask_ratelimit_fetch_ok_total'
                if ($ok1 -gt $ok0) { break }
            }
            Check '插件拉取新版本表成功（ok 净增>0）' ($ok1 -gt $ok0) ("净增=$($ok1 - $ok0)")
        } catch {
            Check '控制面 PUT /ratelimits' $false $_.Exception.Message
        }
    }
}

Write-Host ''
if ($script:failed -eq 0) {
    Write-Host '[PASS] 通道令牌轮换验证全部通过' -ForegroundColor Green
    exit 0
}
Write-Host ("[FAIL] 通道令牌轮换验证失败项=${script:failed}") -ForegroundColor Red
exit 1
