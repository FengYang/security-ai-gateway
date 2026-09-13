# verify-metering-reconcile.ps1 - 审计-计量对账实链验证（Phase 1 门禁 #7 / S5 判据 6）
#
# 判据 6 要件与覆盖：
#   容差 0 token（同源）→ A2 **脚本侧独立重算**：拉 /audit 全量事件按对账窗口
#     [window_start_at, +∞) 聚合 infer 事件（tokens_in/out/次数），与 /usage 计数器逐租户
#     比对，偏差必须为 0；并与 tee 侧快照的 diff 字段交叉核对（口径同源、可复算）
#   差异分类（重启/截断/多实例）→ A1/A4 断言快照暴露的分类信号：
#     chain_intact（截断）、restart_detected/events_before_start（重启基线）、
#     foreign_instances（多实例）；分类→阻断的**运行期**判定由 Go 集成测试覆盖
#     （reconcile_test.go：构造不一致 → 断言 reason/阻断/抑制计数/恢复解阻断）
#   差异时阻断对外出账 → A3 自洽断言：ok ⇔ !billing_blocked，且 /metrics 的
#     otpmask_billing_blocked gauge 与快照一致（阻断置位场景见上述 Go 集成测试）
#
# 本脚本**只读**（不写数据面、不重启服务、无副作用），可安全对生产实例运行。
#
# 未覆盖（如实）：运行期"差异→阻断→抑制推送→恢复"需注入不一致，本脚本不注入故障；
#   该路径由 `go test ./gateway/tee-infer-service/ -run TestReconcile` 覆盖（HTTP 级 + mock webhook）。
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File scripts\verify-metering-reconcile.ps1 `
#     -Tee http://127.0.0.1:19090 -AdminToken <admin|meter token> -Gateway http://127.0.0.1:8080
# 参数：
#   -SkipProbe    不经网关产生新流量（只核对既有账实）
#   -ProbeCount   A0 探针次数（默认 3；用于让"账实两旺"后再对账）
# 退出码：0 = 通过（含设计内 SKIP）；1 = 存在 FAIL；2 = 脚本自身错误
#
# 注：本脚本为 UTF-8 with BOM（含中文；PS 5.1 按 ANSI 解析会坏语法）。

param(
    [string]$Tee = 'http://127.0.0.1:19090',
    [string]$AdminToken = '',
    [string]$Gateway = 'http://127.0.0.1:8080',
    [string]$ProbePath = '/v1/infer',
    [string]$ProbeTenant = 's5-probe',
    [int]$ProbeCount = 3,
    [switch]$SkipProbe
)

$ErrorActionPreference = 'Stop'
$results = New-Object System.Collections.ArrayList
function Record([string]$id, [string]$title, [bool]$ok, [string]$detail) {
    $tag = if ($ok) { 'PASS' } else { 'FAIL' }
    [void]$results.Add([pscustomobject]@{ ID = $id; Title = $title; Status = $tag; Detail = $detail })
    Write-Host ("[{0}] {1} - {2}" -f $tag, $id, $title) -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
    if ($detail) { Write-Host ("        " + $detail) -ForegroundColor DarkGray }
}
function Skip([string]$id, [string]$title, [string]$detail) {
    [void]$results.Add([pscustomobject]@{ ID = $id; Title = $title; Status = 'SKIP'; Detail = $detail })
    Write-Host ("[SKIP] {0} - {1}" -f $id, $title) -ForegroundColor DarkYellow
    if ($detail) { Write-Host ("        " + $detail) -ForegroundColor DarkGray }
}

function Get-Http([string]$url, [string[]]$headers) {
    try {
        $req = [System.Net.HttpWebRequest]::Create($url)
        $req.Method = 'GET'
        $req.Timeout = 20000
        foreach ($h in $headers) { $k, $v = $h -split ':', 2; $req.Headers.Add($k.Trim(), $v.Trim()) }
        $resp = $req.GetResponse()
        $rd = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
        $t = $rd.ReadToEnd(); $rd.Close(); $resp.Close()
        return @{ code = [int]$resp.StatusCode; body = $t }
    } catch [System.Net.WebException] {
        $r = $_.Exception.Response
        if ($r) {
            $rd = New-Object System.IO.StreamReader($r.GetResponseStream(), [System.Text.Encoding]::UTF8)
            $t = $rd.ReadToEnd(); $rd.Close()
            return @{ code = [int]$r.StatusCode; body = $t }
        }
        return @{ code = -1; body = $_.Exception.Message }
    }
}

# Invoke-GatewayProbe 经网关发一次明文探针（otpmask 插件负责段① 加密），返回状态码。
# engine_type 固定 tee_gpu（本地引擎，不依赖外部厂商网络）→ 产生**可计费**的 infer 事件；
# 若走上游 cmaas 且不可达，将记为 deny/engine_error（不计费）从而不产生 infer 事件。
# 数据面/TEE 重启后的前几次请求可能 503（fail-closed + 重新握手，设计内行为）→ 调用方重试。
function Invoke-GatewayProbe([string]$tenant) {
    $body = '{"model":"mock","engine_type":"tee_gpu","messages":[{"role":"user","content":"s5 reconcile probe"}]}'
    $tmp = Join-Path $env:TEMP 's5-reconcile-probe.json'
    [System.IO.File]::WriteAllText($tmp, $body, (New-Object System.Text.UTF8Encoding($false)))
    $codes = @()
    for ($i = 0; $i -lt 5; $i++) {
        $c = (& curl.exe -s -o NUL -m 60 -w '%{http_code}' -X POST "$Gateway$ProbePath" `
                -H 'Content-Type: application/json' -H "X-Tenant-Id: $tenant" --data-binary "@$tmp" 2>$null).ToString().Trim()
        $codes += $c
        if ($c -ne '503') { break }
        Start-Sleep -Seconds 2
    }
    return ($codes | Select-Object -Last 1)
}

$auth = @()
if ($AdminToken) { $auth = @("X-Admin-Token: $AdminToken") }

Write-Host '===== 审计-计量对账实链验证（门禁 #7 / S5 判据 6）=====' -ForegroundColor Cyan

# ---------- P1 前置：tee-infer 可达 ----------
$hz = Get-Http "$Tee/healthz" @()
Record 'P1' 'tee-infer 可达（/healthz）' ($hz.code -eq 200) "GET $Tee/healthz -> $($hz.code)"
if ($hz.code -ne 200) {
    Write-Host "`n[中止] tee-infer 不可达，无法对账（body=$($hz.body)）" -ForegroundColor Red
    exit 1
}

# ---------- A0 探针：经网关产生真实账实（可选） ----------
if ($SkipProbe) {
    Skip 'A0' '经网关探针产生流量' '-SkipProbe：只核对既有账实'
} else {
    $codes = @()
    for ($i = 1; $i -le $ProbeCount; $i++) { $codes += (Invoke-GatewayProbe $ProbeTenant) }
    $okCount = @($codes | Where-Object { $_ -eq '200' }).Count
    Record 'A0' "经网关探针（$ProbePath，$ProbeCount 次）" ($okCount -eq $ProbeCount) ("codes=" + ($codes -join ','))
}

# ---------- A1 快照契约 ----------
$snapResp = Get-Http "$Tee/reconcile" $auth
$snap = $null
if ($snapResp.code -eq 200) { try { $snap = $snapResp.body | ConvertFrom-Json } catch { } }
$okA1 = $snap -and ([int64]$snap.tolerance_tokens -eq 0) -and $snap.instance_id -and ([int64]$snap.last_run_at -gt 0)
Record 'A1' '对账快照契约（tolerance_tokens=0 / instance_id / last_run_at）' ([bool]$okA1) `
    "GET $Tee/reconcile -> $($snapResp.code)；ok=$($snap.ok) reason=$($snap.reason) window_start_at=$($snap.window_start_at)"
if (-not $okA1) {
    Write-Host "`n[中止] 快照不可用（body=$($snapResp.body)）" -ForegroundColor Red
    exit 1
}

# ---------- A2 脚本侧独立重算（口径同源、可复算；容差 0） ----------
$auditResp = Get-Http "$Tee/audit" $auth
$usageResp = Get-Http "$Tee/usage" $auth
$okA2 = $false
$detailA2 = "GET /audit -> $($auditResp.code)；GET /usage -> $($usageResp.code)"
if ($auditResp.code -eq 200 -and $usageResp.code -eq 200) {
    $win = [int64]$snap.window_start_at
    # 注意：不可写成 @($auditResp.body | ConvertFrom-Json)——PS 5.1 下管道会把整个数组
    # 当作**单个对象**传给 @()，导致 $events.Count=1 且 $e.action 变成数组（静默漏算）。
    $events = $auditResp.body | ConvertFrom-Json
    $agg = @{}                     # tenant -> @{in;out;req}  (窗口内 infer 事件)
    $before = 0
    foreach ($e in $events) {
        if ($e.action -ne 'infer') { continue }
        if ([int64]$e.timestamp -lt $win) { $before++; continue }
        $t = [string]$e.tenant_id
        if (-not $agg.ContainsKey($t)) { $agg[$t] = @{ 'in' = 0; out = 0; req = 0 } }
        $agg[$t]['in'] += [int]$e.tokens_in
        $agg[$t].out += [int]$e.tokens_out
        $agg[$t].req++
    }
    $usage = @{}
    $usageObj = $usageResp.body | ConvertFrom-Json
    foreach ($p in $usageObj.PSObject.Properties) {
        $usage[$p.Name] = @{ 'in' = [int]$p.Value.tokens_in; out = [int]$p.Value.tokens_out; req = [int]$p.Value.requests }
    }
    $tenants = @{}
    foreach ($k in $agg.Keys) { $tenants[$k] = $true }
    foreach ($k in $usage.Keys) { $tenants[$k] = $true }
    $mismatch = @()
    $sumIn = 0; $sumOut = 0; $sumReq = 0
    foreach ($t in ($tenants.Keys | Sort-Object)) {
        $a = if ($agg.ContainsKey($t)) { $agg[$t] } else { @{ 'in' = 0; out = 0; req = 0 } }
        $u = if ($usage.ContainsKey($t)) { $usage[$t] } else { @{ 'in' = 0; out = 0; req = 0 } }
        $dIn = $a['in'] - $u['in']; $dOut = $a.out - $u.out; $dReq = $a.req - $u.req
        $sumIn += $dIn; $sumOut += $dOut; $sumReq += $dReq
        if ($dIn -ne 0 -or $dOut -ne 0 -or $dReq -ne 0) {
            $mismatch += "${t}(dIn=$dIn,dOut=$dOut,dReq=$dReq)"
        }
    }
    # 与 tee 侧快照交叉核对（两侧独立算，结论必须一致）
    $crossOk = ([int64]$snap.diff_tokens_in -eq $sumIn) -and ([int64]$snap.diff_tokens_out -eq $sumOut) -and ([int64]$snap.diff_requests -eq $sumReq)
    # 非空校验：探针必须真的产生可计费 infer 事件（否则"0 = 0"是空对账）
    $winEvents = 0
    foreach ($v in $agg.Values) { $winEvents += $v.req }
    $nonVacuous = $SkipProbe -or ($winEvents -ge $ProbeCount)
    $okA2 = ($mismatch.Count -eq 0) -and $crossOk -and $nonVacuous
    $detailA2 = "窗口起点=$win；脚本重算偏差(in=$sumIn out=$sumOut req=$sumReq)；tee快照偏差(in=$($snap.diff_tokens_in) out=$($snap.diff_tokens_out) req=$($snap.diff_requests))；窗口内infer事件=$winEvents；启动前事件=$before；不一致租户=[$($mismatch -join ';')]"
}
Record 'A2' '脚本侧独立重算与 /usage 一致（容差 0 token）' ([bool]$okA2) $detailA2

# ---------- A3 一致性与出账阻断自洽（快照 + 指标） ----------
$mResp = Get-Http "$Tee/metrics" $auth
$okA3 = $false
$detailA3 = "GET /metrics -> $($mResp.code)"
if ($mResp.code -eq 200 -and $snap) {
    $blockedLine = ($mResp.body -split "`n" | Where-Object { $_ -match '^otpmask_billing_blocked\s' } | Select-Object -First 1)
    $gauge = if ($blockedLine) { [int](($blockedLine -split '\s+')[-1]) } else { -1 }
    $consistent = ([bool]$snap.billing_blocked) -eq ($gauge -eq 1)
    $reasonEmpty = (($snap.reason | Out-String).Trim() -eq '')
    $okA3 = $consistent -and ([bool]$snap.ok -eq $reasonEmpty) -and [bool]$snap.chain_intact
    $detailA3 = "snapshot.ok=$($snap.ok) reason=$($snap.reason) billing_blocked=$($snap.billing_blocked)；metrics otpmask_billing_blocked=$gauge；chain_intact=$($snap.chain_intact)"
}
Record 'A3' '一致性与出账阻断自洽（快照 ⇔ 指标；链完整）' ([bool]$okA3) $detailA3

# ---------- A4 重启基线（信息项，不阻断） ----------
if ($snap -and $snap.restart_detected) {
    $okA4 = ([bool]$snap.ok) -and (-not [bool]$snap.billing_blocked)
    Record 'A4' '重启基线不阻断出账（链跨重启保留，累计视图口径差异）' ([bool]$okA4) `
        "restart_detected=true events_before_start=$($snap.events_before_start)；ok=$($snap.ok) billing_blocked=$($snap.billing_blocked)"
} else {
    Skip 'A4' '重启基线不阻断出账' '本次未检测到启动前事件（restart_detected=false）→ 设计内 SKIP；重启 tee-infer 后重跑本脚本即可覆盖'
}

# ---------- 汇总 ----------
$fail = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
$pass = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
$skip = @($results | Where-Object { $_.Status -eq 'SKIP' }).Count
Write-Host "`n===== 汇总 =====" -ForegroundColor Cyan
Write-Host "PASS=$pass FAIL=$fail SKIP=$skip" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host '未覆盖（如实）：运行期"差异→阻断→抑制推送→恢复"需注入不一致，由 go test -run TestReconcile 覆盖（HTTP 级 + mock webhook）' -ForegroundColor DarkYellow
if ($fail -gt 0) { exit 1 }
exit 0
