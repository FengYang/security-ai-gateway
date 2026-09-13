# verify-shadow-plaintext-e2e.ps1 — 门禁 #7 边界 A：明文路由 RPM 影子执行器 实链验收
#
# 覆盖（方案《GA-门禁7-剩余能力边界-实现方案.md》§A.5）：
#   [1] 前置：数据面插件已加载（Envoy stats 有 rpm-shadow VM）且 CR 内 shadow_enabled=true（config_dump）
#   [2] 控制面下发影子规则（kind=rate + action=shadow，rpm=1）→ 插件拉表（K_rx 验签出入）
#   [3] 造超阈流量 → 插件指标 otpmask_shadow_would_reject_total 净增 > 0，且**请求不含 429**（影子不拒绝）
#   [4] 窗口级汇总上报 → tee-infer /audit/shadow 落链（accepted 净增）+ /audit 可见该租户 shadow/would_reject
#   [5] 独立验证器 audit-verify -schema tee 判定链完整（ok=true）
#   [6] 失败路径：停 tee-infer → report_fail 净增、请求仍不含 429（不阻塞业务）→ 恢复
#
# 前置（本地）：standalone Higress 容器（rpm-shadow 插件已挂载 + CR 为运行态）+
#   gateway-core(:8085，含 K_rx) + tee-infer(:19090，含 /audit/shadow) + 网关入口(:8080)
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File scripts\verify-shadow-plaintext-e2e.ps1 `
#     -CoreToken <OTP_CORE_AUTH_TOKEN> [-Tenant t-shadow] [-Consumer a-probe-consumer] [-Probes 40]
#
# 退出码：0 全 PASS；1 有 FAIL；2 参数/环境错误

param(
    [string]$Core = 'http://127.0.0.1:8085',
    [Parameter(Mandatory = $true)][string]$CoreToken,
    [string]$Tee = 'http://127.0.0.1:19090',
    [string]$Gateway = 'http://127.0.0.1:8080',
    [string]$Container = 'higress-chain-control-plane',
    [string]$TeeContainer = 'otpmask-plugin-tee-infer-service-1',
    [string]$Tenant = 't-shadow',
    [string]$Consumer = 'a-probe-consumer',
    [int]$Probes = 40,
    [int]$RolloverWaitSeconds = 75
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

# Invoke-Json HTTP 请求（返回状态码 + body）。
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

# Get-PluginStat 读数据面插件 counter（多 worker 累加）。
function Get-PluginStat([string]$name) {
    $out = & docker exec $Container sh -c "curl -s http://127.0.0.1:15000/stats | grep wasmcustom.$name" 2>$null
    if ($out -match ":\s*(\d+)") { return [int]$Matches[1] }
    return 0
}

# Get-TeeStat 读 tee-infer 指标（文本格式）。
function Get-TeeStat([string]$name, [string]$selector) {
    $text = (curl.exe -s "$Tee/metrics" 2>$null | Out-String)
    foreach ($line in ($text -split "`n")) {
        if ($line -match ("^" + [regex]::Escape($name) + "\{" + [regex]::Escape($selector) + "\}\s+(\d+)")) {
            return [int]$Matches[1]
        }
    }
    return 0
}

# Invoke-Infer 经网关发密态推理（健康上游，用于造流量而不引入上游噪声）。
function Invoke-Infer([string]$tenant, [string]$consumer) {
    $tmp = Join-Path $env:TEMP 'a-shadow-probe.json'
    [System.IO.File]::WriteAllText($tmp, '{"text":"shadow probe"}', (New-Object System.Text.UTF8Encoding($false)))
    $out = & curl.exe -s -m 15 -o NUL -w '%{http_code}' -X POST -H "Content-Type: application/json" `
        -H "X-Tenant-ID: $tenant" -H "x-mse-consumer: $consumer" --data-binary "@$tmp" "$Gateway/v1/infer" 2>$null
    return [int]$out.ToString().Trim()
}

Write-Host '== 门禁 #7 边界 A：明文路由 RPM 影子执行器 实链 ==' -ForegroundColor Cyan

# [1] 前置
Write-Host '[1] 前置：插件加载 + CR 生效（shadow_enabled）' -ForegroundColor Yellow
$stats = & docker exec $Container sh -c "curl -s http://127.0.0.1:15000/stats" 2>$null | Out-String
Check 'rpm-shadow 插件 VM 已创建' ($stats -match 'wasmplugin/higress-system\.rpm-shadow') ''
$dump = & docker exec $Container sh -c "curl -s http://127.0.0.1:15000/config_dump" 2>$null | Out-String
Check 'CR 内 shadow_enabled=true（config_dump）' ($dump -match 'shadow_enabled\\":\\"true') ''
$teeHealth = Invoke-Json 'GET' "$Tee/healthz" ''
if ($teeHealth.code -ne 200) {
    Write-Host "  [FAIL] tee-infer 不可达（$Tee/healthz → $($teeHealth.code)）：先启动 tee-infer（含 /audit/shadow）" -ForegroundColor Red
    exit 2
}
Check 'tee-infer /healthz 200（含 /audit/shadow 端点）' ($teeHealth.code -eq 200) ''

# [2] 下发影子规则
Write-Host '[2] 控制面下发影子规则（kind=rate + action=shadow，rpm=1）' -ForegroundColor Yellow
$cur = Invoke-Json 'GET' "$Core/ratelimits" '' $CoreToken
if ($cur.code -ne 200) {
    Write-Host "  [FAIL] 读取限流表失败 HTTP=$($cur.code)（gateway-core 未运行或令牌错误）" -ForegroundColor Red
    exit 2
}
$nextVer = [int](($cur.body | ConvertFrom-Json).version) + 1
$now = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$policy = @{
    version   = $nextVer
    issued_at = $now
    rules     = @(
        @{ id = 'a-e2e-tenant-shadow'; kind = 'rate'; scope = 'tenant'; target = $Tenant; rpm = 1; action = 'shadow'; enabled = $true },
        @{ id = 'a-e2e-apikey-shadow'; kind = 'rate'; scope = 'api_key'; target = $Consumer; rpm = 1; action = 'shadow'; enabled = $true }
    )
} | ConvertTo-Json -Depth 6 -Compress
$put = Invoke-Json 'PUT' "$Core/ratelimits" $policy $CoreToken
Check '控制面接受影子规则表' ($put.code -eq 200) "version=$nextVer code=$($put.code)"
$fetchOKBefore = Get-PluginStat 'otpmask_shadow_table_fetch_ok_total'
Write-Host ("  等待插件拉表（table_fetch_ok 基线={0}）" -f $fetchOKBefore) -ForegroundColor DarkGray
$deadline = (Get-Date).AddSeconds(70)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 5
    if ((Get-PluginStat 'otpmask_shadow_table_fetch_ok_total') -gt $fetchOKBefore) { break }
}
Check '插件已拉取新表（K_rx 验签通过）' ((Get-PluginStat 'otpmask_shadow_table_fetch_ok_total') -gt $fetchOKBefore) `
    ("table_fetch_ok={0}" -f (Get-PluginStat 'otpmask_shadow_table_fetch_ok_total'))

# [3] 造超阈流量（影子只计数不拒绝）
Write-Host ("[3] 造超阈流量（{0} 次；rpm=1 × 16 worker ⇒ 期望命中）" -f $Probes) -ForegroundColor Yellow
# 预热（既有行为，非本边界引入）：tee-infer 重启后各 worker 仍持旧 K_enc 会话，
# 其首个 key/issue 被 TEE 判 401 → otpmask fail-closed 503 并触发重握手（网关日志
# "TEE 密钥签发失败 401（会话失效，已触发重握手）"）。session 为 per-worker（16 worker），
# 故冷启动下前若干请求可能 503，与影子插件无关（影子插件从不产生该响应）。
# ⇒ 先逐连接预热至连续 200，再进入计量窗口，避免把会话恢复误判为"影子阻断"。
$warmStreak = 0
$warmCount = 0
$warmLast = 0
while ($warmCount -lt 40 -and $warmStreak -lt 6) {
    $warmLast = Invoke-Infer $Tenant $Consumer
    $warmCount++
    if ($warmLast -eq 200) { $warmStreak++ } else { $warmStreak = 0 }
}
Write-Host ("  预热：{0} 次（连续 200={1}，末次={2}）" -f $warmCount, $warmStreak, $warmLast) -ForegroundColor DarkGray
Check 'tee 会话预热收敛（连续 200 ≥ 6）' ($warmStreak -ge 6) "末次=$warmLast"
$wrBefore = Get-PluginStat 'otpmask_shadow_would_reject_total'
$codes = @()
for ($i = 1; $i -le $Probes; $i++) { $codes += (Invoke-Infer $Tenant $Consumer) }
$ok200 = @($codes | Where-Object { $_ -eq 200 }).Count
$n429 = @($codes | Where-Object { $_ -eq 429 }).Count
$statuses = ($codes | Group-Object | ForEach-Object { "$($_.Name)×$($_.Count)" }) -join ' '
Check '请求全部 200（影子不拒绝）' ($ok200 -eq $Probes) "状态码: $statuses"
Check '无 429（影子不执行限流）' ($n429 -eq 0) "429×$n429"
$wrAfter = Get-PluginStat 'otpmask_shadow_would_reject_total'
Check '影子命中计数净增（would_reject）' ($wrAfter -gt $wrBefore) "before=$wrBefore after=$wrAfter"

# [4] 窗口级汇总上报 → 落链
Write-Host ('[4] 窗口级汇总上报 → tee-infer /audit/shadow 落链（等窗口翻转 ≤{0}s）' -f $RolloverWaitSeconds) -ForegroundColor Yellow
$accBefore = Get-TeeStat 'otpmask_shadow_reports_total' 'result="accepted"'
$sentBefore = Get-PluginStat 'otpmask_shadow_report_sent_total'
$deadline = (Get-Date).AddSeconds($RolloverWaitSeconds)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 6
    if ((Get-TeeStat 'otpmask_shadow_reports_total' 'result="accepted"') -gt $accBefore) { break }
}
$accAfter = Get-TeeStat 'otpmask_shadow_reports_total' 'result="accepted"'
Check 'tee-infer 接受窗口级汇总（accepted 净增）' ($accAfter -gt $accBefore) "before=$accBefore after=$accAfter"
Check '插件上报成功计数净增' ((Get-PluginStat 'otpmask_shadow_report_sent_total') -gt $sentBefore) `
    ("sent={0}" -f (Get-PluginStat 'otpmask_shadow_report_sent_total'))
$audit = (Invoke-Json 'GET' "$Tee/audit?tenant=$Tenant" '').body
$shadowEvents = ([regex]::Matches($audit, '"action":"shadow"')).Count
Check '审计可见该租户 shadow 事件' ($shadowEvents -gt 0) "events=$shadowEvents"
$wouldReject = ([regex]::Matches($audit, '"result":"would_reject"')).Count
Check '审计可见 would_reject 结论' ($wouldReject -gt 0) "events=$wouldReject"
$verify = (Invoke-Json 'GET' "$Tee/audit/verify" '').body
Check 'tee 自校验链完整（/audit/verify ok）' ($verify -match '"ok":true') ''

# [5] 独立验证器：audit-verify -schema tee
Write-Host '[5] 独立验证器 audit-verify -schema tee' -ForegroundColor Yellow
$chainFile = Join-Path $env:TEMP 'a-tee-audit.jsonl'
& docker cp "$TeeContainer`:/tmp/tee-audit.jsonl" $chainFile | Out-Null
$av = & go run -mod=mod ./gateway/audit-verify/cmd/audit-verify -file $chainFile -schema tee -json 2>&1 | Out-String
Check 'audit-verify 判定链完整（ok=true）' ($av -match '"ok":\s*true') (($av -replace "`n", ' ').Trim().Substring(0, [Math]::Min(160, ($av -replace "`n", ' ').Trim().Length)))

# [6] 失败路径：停 tee-infer（上报失败不阻塞业务）
Write-Host '[6] 失败路径：停 tee-infer → 上报失败计数增长、业务不含 429' -ForegroundColor Yellow
$failBefore = Get-PluginStat 'otpmask_shadow_report_fail_total'
& docker stop $TeeContainer | Out-Null
Start-Sleep -Seconds 8
$codes2 = @(); for ($i = 1; $i -le 8; $i++) { $codes2 += (Invoke-Infer $Tenant $Consumer) }
$n429b = @($codes2 | Where-Object { $_ -eq 429 }).Count
Check 'tee 停机期间无 429（不阻塞业务）' ($n429b -eq 0) ("状态码: " + (($codes2 | Group-Object | ForEach-Object { "$($_.Name)×$($_.Count)" }) -join ' '))
# 上报只在"窗口翻转结算 + flush tick"发生 → 须等一次翻转，失败才必然可见（≤75s）
$deadline = (Get-Date).AddSeconds(75)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 6
    if ((Get-PluginStat 'otpmask_shadow_report_fail_total') -gt $failBefore) { break }
}
$failAfter = Get-PluginStat 'otpmask_shadow_report_fail_total'
Check '上报失败计数净增（有界重试，不静默）' ($failAfter -gt $failBefore) "before=$failBefore after=$failAfter"
& docker start $TeeContainer | Out-Null
Start-Sleep -Seconds 10
Check 'tee-infer 已恢复（healthz 200）' ((Invoke-Json 'GET' "$Tee/healthz" '').code -eq 200) ''

Write-Host ''
if ($script:failed -eq 0) {
    Write-Host '[PASS] 边界 A 明文路由影子执行器 实链验收全部通过' -ForegroundColor Green
    exit 0
}
Write-Host ("[FAIL] 边界 A 实链失败项=${script:failed}") -ForegroundColor Red
exit 1
