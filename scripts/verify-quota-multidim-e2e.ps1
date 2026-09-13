# verify-quota-multidim-e2e.ps1 — 门禁 #7 边界 B：tee-infer 多维度 enforce 实链验收
#
# 覆盖（方案《GA-门禁7-剩余能力边界-实现方案.md》§B.5）：
#   [1] 多维度下发：PUT gateway-core /ratelimits（同租户 tpm + 日预算）→ tee_applied=true、
#       tee_updates=2、Note 含"多维 enforce"
#   [2] 运行态快照：tee-infer /usage 的 quota_limits[] 含两个维度（minute/day）
#   [3] 维度归因：分别把两个租户打到 429，断言 otpmask_quota_denies_total{window} 归因正确
#       （t-multi → minute；t-day → day）
#   [4] 兼容：扁平写法（S3b）仍 200 且窗口生效；冲突/重复 window → 400
#   [5] 窗口翻转隔离（-WaitMinuteRollover）：分钟翻转只重置 minute 维度，day 维度计数不受影响
#
# 前置（本地 compose + standalone 混合栈）：tee-infer(:19090 新版) + gateway-core(:8085，
# 需 OTP_CORE_TEE_URL 指向 tee-infer 以启用配额下发) + compose envoy(:10000，/infer 探针)。
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File scripts\verify-quota-multidim-e2e.ps1 `
#     -CoreToken <OTP_CORE_AUTH_TOKEN> [-WaitMinuteRollover]
#
# 退出码：0 全 PASS；1 有 FAIL；2 参数/环境错误

param(
    [string]$Core = 'http://127.0.0.1:8085',
    [Parameter(Mandatory = $true)][string]$CoreToken,
    [string]$Tee = 'http://127.0.0.1:19090',
    [string]$Gateway = 'http://127.0.0.1:10000',
    [int]$ProbeCap = 8,
    [switch]$WaitMinuteRollover
)

$ErrorActionPreference = 'Stop'
$script:failed = 0

function Check([string]$name, [bool]$ok, [string]$detail = '') {
    $tag = if ($ok) { 'PASS' } else { 'FAIL' }
    if (-not $ok) { $script:failed++ }
    $color = 'Green'
    if (-not $ok) { $color = 'Red' }
    Write-Host ("  [{0}] {1} {2}" -f $tag, $name, $detail) -ForegroundColor $color
}

# Invoke-Json 发起 JSON 请求（返回状态码 + body），fail-closed 判定不抛异常。
function Invoke-Json([string]$method, [string]$url, [string]$body, [string]$bearer = '') {
    $req = [System.Net.HttpWebRequest]::Create($url)
    $req.Method = $method
    $req.Timeout = 20000
    if ($bearer) { $req.Headers.Add('Authorization', "Bearer $bearer") }
    if ($body) {
        $req.ContentType = 'application/json'
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
        $req.ContentLength = $bytes.Length
        $s = $req.GetRequestStream(); $s.Write($bytes, 0, $bytes.Length); $s.Close()
    }
    try {
        $resp = $req.GetResponse()
        $code = [int]$resp.StatusCode
        $rd = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
        $text = $rd.ReadToEnd(); $rd.Close(); $resp.Close()
        return @{ code = $code; body = $text }
    } catch [System.Net.WebException] {
        $r = $_.Exception.Response
        if ($r) { return @{ code = [int]$r.StatusCode; body = '' } }
        return @{ code = -1; body = $_.Exception.Message }
    }
}

# Invoke-Infer 经网关发一次密态 text 推理（tenant 头决定配额归属），返回状态码。
function Invoke-Infer([string]$tenant) {
    $tmp = Join-Path $env:TEMP 'b-infer-probe.json'
    [System.IO.File]::WriteAllText($tmp, '{"text":"hello"}', (New-Object System.Text.UTF8Encoding($false)))
    $out = & curl.exe -s -m 30 -o NUL -w '%{http_code}' -X POST -H "Content-Type: application/json" `
        -H "X-Tenant-ID: $tenant" --data-binary "@$tmp" "$Gateway/infer" 2>$null
    return [int]$out.ToString().Trim()
}

# Metric-Value 读取 tee-infer 某指标族的某标签样本值（无该样本返回 0）。
function Metric-Value([string]$name, [string]$selector) {
    $text = (curl.exe -s "$Tee/metrics" 2>$null | Out-String)
    foreach ($line in ($text -split "`n")) {
        if ($line -match ("^" + [regex]::Escape($name) + "\{" + [regex]::Escape($selector) + "\}\s+(\d+)")) {
            return [int]$Matches[1]
        }
    }
    return 0
}

Write-Host '== 门禁 #7 边界 B：tee-infer 多维度 enforce 实链 ==' -ForegroundColor Cyan

# [1] 多维度下发
Write-Host '[1] 控制面多维度下发（tpm → minute；日预算 → day，同租户并存）' -ForegroundColor Yellow
$cur = Invoke-Json 'GET' "$Core/ratelimits" '' $CoreToken
if ($cur.code -ne 200) {
    Write-Host "  [FAIL] 读取当前限流表失败 HTTP=$($cur.code)（core 是否在跑且令牌正确？）" -ForegroundColor Red
    exit 2
}
$curVer = [int](($cur.body | ConvertFrom-Json).version)
$nextVer = $curVer + 1
$now = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$policy = @{
    version   = $nextVer
    issued_at = $now
    rules     = @(
        @{ id = 'b-e2e-multi-rate'; kind = 'rate'; scope = 'tenant'; target = 't-multi'; rpm = 600; tpm = 5; action = 'reject'; enabled = $true },
        @{ id = 'b-e2e-multi-budget'; kind = 'budget'; scope = 'tenant'; target = 't-multi'; daily_budget_tokens = 10; action = 'reject'; enabled = $true },
        @{ id = 'b-e2e-day-budget'; kind = 'budget'; scope = 'tenant'; target = 't-day'; daily_budget_tokens = 3; action = 'reject'; enabled = $true }
    )
} | ConvertTo-Json -Depth 6 -Compress
$put = Invoke-Json 'PUT' "$Core/ratelimits" $policy $CoreToken
if ($put.code -ne 200) {
    Write-Host "  [FAIL] PUT /ratelimits HTTP=$($put.code) body=$($put.body)" -ForegroundColor Red
    exit 2
}
$pr = $put.body | ConvertFrom-Json
Check '控制面接受新版本表' ($pr.version -eq $nextVer) "version=$($pr.version)"
Check 'TEE 侧下发成功（tee_applied）' ([bool]$pr.tee_applied) "tee_updates=$($pr.tee_updates)"
Check '同租户两维度合并且各占一条 limit' ($pr.tee_updates -eq 2) "tee_updates=$($pr.tee_updates)"
$notesJoined = ($pr.notes -join '|')
Check 'Note 说明多维 enforce 语义' ($notesJoined -match '多维 enforce') ''
Check 'Note 分别说明 minute/day 窗口' (($notesJoined -match '每分钟窗口') -and ($notesJoined -match 'UTC\+8 自然日窗口')) ''

# [2] 运行态快照
Write-Host '[2] tee-infer 运行态 quota_limits[]' -ForegroundColor Yellow
$usage = (Invoke-Json 'GET' "$Tee/usage?tenant=t-multi" '').body | ConvertFrom-Json
$umi = $usage.'t-multi'
$dims = $umi.quota_limits
Check 't-multi 含 2 个 enforce 维度' ($dims.Count -eq 2) ("dims=" + (($dims | ForEach-Object { $_.window }) -join ','))
Check '兼容字段取主维度（minute）' ($umi.quota_window -eq 'minute' -and $umi.quota -eq 5) "quota=$($umi.quota) window=$($umi.quota_window)"
$uday = ((Invoke-Json 'GET' "$Tee/usage?tenant=t-day" '').body | ConvertFrom-Json).'t-day'
Check 't-day 单维度（day）快照' ($uday.quota_limits.Count -eq 1 -and $uday.quota_limits[0].window -eq 'day') ("dims=" + (($uday.quota_limits | ForEach-Object { $_.window }) -join ','))

# [3] 维度归因：用两个**独立租户**分别把 minute / day 打满（另一维度留足余额），
#     断言拒绝归因到正确维度且不误记到另一维度（租户与计数自建，可重复运行）。
Write-Host '[3] 两个维度分别触发 429 并按维度归因' -ForegroundColor Yellow
$cases = @(
    @{ tenant = 'b-min'; limits = '[{"window":"minute","max_tokens":2},{"window":"day","max_tokens":1000000}]'; window = 'minute'; other = 'day' },
    @{ tenant = 'b-daydim'; limits = '[{"window":"minute","max_tokens":1000000},{"window":"day","max_tokens":2}]'; window = 'day'; other = 'minute' }
)
foreach ($case in $cases) {
    $tenant = $case.tenant; $window = $case.window; $other = $case.other
    $null = Invoke-Json 'POST' "$Tee/usage/quota" ('{"tenant":"' + $tenant + '","limits":' + $case.limits + '}')
    $sel = "tenant=`"$tenant`",window=`"$window`""
    $before = Metric-Value 'otpmask_quota_denies_total' $sel
    $codes = @()
    for ($i = 1; $i -le $ProbeCap; $i++) {
        $codes += (Invoke-Infer $tenant)
        if ($codes[-1] -eq 429) { break }
    }
    $after = Metric-Value 'otpmask_quota_denies_total' $sel
    Check ("t={0} 在 {1} 次内触发 429" -f $tenant, $ProbeCap) ($codes[-1] -eq 429) ("codes=" + ($codes -join ','))
    Check ("拒绝按 window={0} 归因" -f $window) ($after -gt $before) "before=$before after=$after"
    $otherVal = Metric-Value 'otpmask_quota_denies_total' ("tenant=`"$tenant`",window=`"$other`"")
    Check ("另一维度（{0}）未被误记为拒绝原因" -f $other) ($otherVal -eq 0) "other_denies=$otherVal"
}

# [4] 兼容与冲突校验
Write-Host '[4] 扁平兼容（S3b）与冲突校验' -ForegroundColor Yellow
$flat = Invoke-Json 'POST' "$Tee/usage/quota" '{"tenant":"b-flat","max_tokens":50,"window":"minute"}'
$flatOut = $flat.body | ConvertFrom-Json
Check '扁平写法 200 且窗口生效' ($flat.code -eq 200 -and $flatOut.window -eq 'minute' -and $flatOut.quota -eq 50) "code=$($flat.code)"
Check '扁平写法等价于单维度 limits' ($flatOut.quota_limits.Count -eq 1 -and $flatOut.quota_limits[0].window -eq 'minute') ''
$conflict = Invoke-Json 'POST' "$Tee/usage/quota" '{"tenant":"b-flat","max_tokens":10,"limits":[{"max_tokens":20}]}'
Check 'limits 与扁平同现 → 400' ($conflict.code -eq 400) "code=$($conflict.code)"
$dup = Invoke-Json 'POST' "$Tee/usage/quota" '{"tenant":"b-flat","limits":[{"window":"day","max_tokens":1},{"window":"day","max_tokens":2}]}'
Check '重复 window → 400' ($dup.code -eq 400) "code=$($dup.code)"

# [5] 窗口翻转隔离（可选）：用**独立租户**自证（minute=2 打满 → 跨分钟翻转 → 放行且 day 继续累加），
#     与前面步骤的累计计数解耦，可重复运行。
if ($WaitMinuteRollover) {
    Write-Host '[5] 窗口翻转隔离（minute 重置 / day 不受影响）' -ForegroundColor Yellow
    $rt = 'b-roll'
    $null = Invoke-Json 'POST' "$Tee/usage/quota" ('{"tenant":"' + $rt + '","limits":[{"window":"minute","max_tokens":2},{"window":"day","max_tokens":1000000}]}')
    $codes = @()
    for ($i = 1; $i -le 4; $i++) {
        $codes += (Invoke-Infer $rt)
        if ($codes[-1] -eq 429) { break }
    }
    Check '打满 minute 维度（出现 429）' ($codes[-1] -eq 429) ("codes=" + ($codes -join ','))
    $r0 = ((Invoke-Json 'GET' "$Tee/usage?tenant=$rt" '').body | ConvertFrom-Json).($rt)
    $m0 = ($r0.quota_limits | Where-Object { $_.window -eq 'minute' }).window_used
    $d0 = ($r0.quota_limits | Where-Object { $_.window -eq 'day' }).window_used
    $wait = 60 - (Get-Date).Second + 3
    Write-Host ("  等待分钟翻转（{0}s）" -f $wait) -ForegroundColor DarkGray
    Start-Sleep -Seconds $wait
    $code = Invoke-Infer $rt
    $r1 = ((Invoke-Json 'GET' "$Tee/usage?tenant=$rt" '').body | ConvertFrom-Json).($rt)
    $m1 = ($r1.quota_limits | Where-Object { $_.window -eq 'minute' }).window_used
    $d1 = ($r1.quota_limits | Where-Object { $_.window -eq 'day' }).window_used
    Check '翻转后放行（minute 维度已重置）' ($code -eq 200) "HTTP=$code"
    Check 'minute 维度计数回落' ($m1 -lt $m0) "before=$m0 after=$m1"
    Check 'day 维度计数未被翻转重置（继续累加）' ($d1 -gt $d0) "before=$d0 after=$d1"
} else {
    Write-Host '[5] [SKIP] 未指定 -WaitMinuteRollover（窗口翻转隔离由单测覆盖）' -ForegroundColor DarkYellow
}

Write-Host ''
if ($script:failed -eq 0) {
    Write-Host '[PASS] 边界 B 多维度 enforce 实链验收全部通过' -ForegroundColor Green
    exit 0
}
Write-Host ("[FAIL] 边界 B 实链失败项=${script:failed}") -ForegroundColor Red
exit 1
