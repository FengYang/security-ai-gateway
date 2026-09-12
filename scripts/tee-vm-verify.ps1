# tee-vm-verify.ps1 - GPU-TEE / CPU-TEE 云主机验证驱动（本机操作侧）
#
# 定位：本机（Windows）驱动**远端** TEE 云主机（CPU-TEE = TDX 机密 VM；GPU-TEE = H100 机密计算实例）
#       完成「环境自检 → 证明链核验 → 密态 E2E → 性能采集 → 报告落盘」。
#       guest 侧硬件就绪度由 scripts/check-tdx-vm.sh 在 VM 内探测，其输出经 -GuestCheckFile 并入本报告。
#
# 为什么不在 VM 内跑本脚本：密态链路的段①加密/解密在网关侧（otpmask wasm），
# 故 E2E 必须打远端网关 :8080；本机侧脚本免去在 VM 内装 PowerShell 的依赖。
#
# 前置：
#   1) 远端已按《GA-TEE虚拟机验证准备包.md》起 gateway :8080 + tee-infer :19090（tdx/GPU 模式）
#   2) 本机能直连上述两个端口（安全组/防火墙放行）
#   3) -AdminToken：tee 若以 -admin-token 启动，读 /audit /metrics 需携带（默认空=开发模式不校验）
#   4) E2E 期望 tee 已配 -cmaas-url 或 -engine-url（否则 /v1/infer fail-closed 503）
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File scripts\tee-vm-verify.ps1 `
#       -Gateway http://<vm-ip>:8080 -Tee http://<vm-ip>:19090 -ExpectEnclave tdx `
#       -AdminToken <token> -GuestCheckFile .\check-tdx-vm.out.txt
#   退出码：0 = 全部 PASS（SKIP 不计失败）；1 = 存在 FAIL；2 = 脚本自身错误
#
# 注：本脚本为 UTF-8 with BOM（含中文；PS 5.1 按 ANSI 解析会坏语法）。

param(
    [string]$Gateway = 'http://127.0.0.1:8080',
    [string]$Tee = 'http://127.0.0.1:19090',
    [string]$AdminToken = '',
    [ValidateSet('mock', 'tdx')][string]$ExpectEnclave = 'tdx',
    [int]$Rounds = 3,
    [string]$OutDir = '',
    [string]$GuestCheckFile = '',
    [int]$WarmMaxAttempts = 24,
    [switch]$SkipE2E,
    [switch]$SkipPerf
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $repo ('.tools\tee-vm-verify\' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
$adminHeaders = @()
if ($AdminToken) { $adminHeaders = @("X-Admin-Token: $AdminToken") }

$results = New-Object System.Collections.ArrayList
function Record([string]$id, [string]$title, [bool]$ok, [string]$detail) {
    $tag = if ($ok) { 'PASS' } else { 'FAIL' }
    [void]$results.Add([pscustomobject]@{ ID = $id; Title = $title; Status = $tag; Detail = $detail })
    Write-Host ("[{0}] {1} - {2}" -f $tag, $id, $title) -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
    if ($detail) { Write-Host ("        " + $detail) -ForegroundColor DarkGray }
}
function RecordSkip([string]$id, [string]$title, [string]$detail) {
    [void]$results.Add([pscustomobject]@{ ID = $id; Title = $title; Status = 'SKIP'; Detail = $detail })
    Write-Host ("[SKIP] {0} - {1}" -f $id, $title) -ForegroundColor DarkYellow
    if ($detail) { Write-Host ("        " + $detail) -ForegroundColor DarkGray }
}

function Sha256Hex([byte[]]$bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash($bytes)) | ForEach-Object { $_.ToString('x2') }) -join '' }
    finally { $sha.Dispose() }
}

function HexToBytes([string]$hex) {
    $out = New-Object byte[] ($hex.Length / 2)
    for ($i = 0; $i -lt $out.Length; $i++) { $out[$i] = [convert]::ToByte($hex.Substring($i * 2, 2), 16) }
    return , $out
}

function Exec([string]$url, [string]$method = 'GET', [string]$body = '', [string[]]$headers = @(), [int]$timeoutSec = 30) {
    $bytes = if ($body) { [System.Text.Encoding]::UTF8.GetBytes($body) } else { $null }
    $req = [System.Net.HttpWebRequest]::Create($url)
    $req.Method = $method
    $req.Timeout = $timeoutSec * 1000
    $req.ReadWriteTimeout = $timeoutSec * 1000
    foreach ($h in $headers) { $k, $v = $h -split ':', 2; $req.Headers.Add($k.Trim(), $v.Trim()) }
    if ($bytes) { $req.ContentType = 'application/json'; $req.ContentLength = $bytes.Length }
    try {
        if ($bytes) { $s = $req.GetRequestStream(); $s.Write($bytes, 0, $bytes.Length); $s.Close() }
        $resp = $req.GetResponse()
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) {
            $r = $_.Exception.Response
            $rd = New-Object System.IO.StreamReader($r.GetResponseStream(), [System.Text.Encoding]::UTF8)
            return [pscustomobject]@{ Code = [int]$r.StatusCode; Body = $rd.ReadToEnd() }
        }
        throw
    }
    $reader = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
    $text = $reader.ReadToEnd()
    $reader.Close(); $resp.Close()
    return [pscustomobject]@{ Code = [int]$resp.StatusCode; Body = $text }
}

# ---------- 1. 环境自检 ----------
Write-Host "`n===== 1. 环境自检 =====" -ForegroundColor Cyan
$gw = $null
try { $gw = Exec "$Gateway/" 'GET' '' @() 10 } catch { $gw = $null }
Record 'P1' '远端网关可达' ([bool]$gw) "Gateway=$Gateway"

$metrics = Exec "$Tee/metrics" 'GET' '' $adminHeaders 15
$teeAlive = ($metrics.Code -eq 200 -or $metrics.Code -eq 401)
Record 'P2' '远端 tee-infer 可达（/metrics 200 或 401=需令牌）' ([bool]$teeAlive) `
    "Tee=$Tee code=$($metrics.Code)"

# ---------- 2. 证明链核验（真 Quote / report_data 绑定） ----------
Write-Host "`n===== 2. 证明链核验 =====" -ForegroundColor Cyan
$nonceBytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nonceBytes)
$nonceHex = ($nonceBytes | ForEach-Object { $_.ToString('x2') }) -join ''
$ar = Exec "$Tee/attest" 'POST' ("{`"nonce`":`"$nonceHex`"}") @() 60
$attest = $null
try { $attest = $ar.Body | ConvertFrom-Json } catch { $attest = $null }

Record 'A1' '/attest 200 且 status=attested' ($ar.Code -eq 200 -and $attest -and $attest.status -eq 'attested') `
    "code=$($ar.Code) status=$($attest.status)"
if ($attest) {
    $platform = $attest.proof.platform
    $wantMock = ($ExpectEnclave -eq 'mock')
    Record 'A2' "证明平台与期望一致（期望 $ExpectEnclave）" ($platform -eq $ExpectEnclave) "platform=$platform"
    Record 'A3' 'nonce 回显与挑战一致' ($attest.proof.nonce -eq $nonceHex) "nonce=$($nonceHex.Substring(0,16))..."
    # report_data = SHA256(nonce ‖ server_pub)：本机独立重算，证明握手公钥未被替换（RA-TLS 绑定）
    $bindBytes = (HexToBytes $nonceHex) + (HexToBytes $attest.server_pub)
    $want = Sha256Hex $bindBytes
    $gotRd = "$($attest.proof.report_data)"
    Record 'A4' 'report_data == SHA256(nonce‖server_pub)（本机重算）' ($gotRd -eq $want) `
        "got=$($gotRd.Substring(0, [Math]::Min(16, $gotRd.Length)))... want=$($want.Substring(0,16))..."
    # 真 TDX 必须有 Quote 原文（mock 为 0 且不输出 quote 字段）
    $quoteLen = [int]$attest.proof.quote_len
    if ($wantMock) {
        Record 'A5' 'mock 模式不产出 Quote（预期）' ($quoteLen -eq 0) "quote_len=$quoteLen"
    } else {
        $quoteHex = $attest.proof.quote
        Record 'A5' '真 TDX Quote 非空（可交 DCAP 独立验签）' `
            ($quoteLen -gt 0 -and $quoteHex -and $quoteHex.Length -gt 1000) `
            "quote_len=$quoteLen quote_hex=$($quoteHex.Length) 字符"
        $mkeys = if ($attest.proof.measurements) { ($attest.proof.measurements.PSObject.Properties.Name) -join ',' } else { '' }
        Record 'A6' 'TDX 度量值齐备（MRTD/RTMR 等）' ($mkeys -ne '') "measurements=[$mkeys]"
    }
}

# ---------- 3. 密态 E2E（经网关，段①加密 + TEE 解密 + SSE 增量解密） ----------
$e2eCodes = @()
$warmFails = 0
$plainText = ''
$auditLastInfer = $null
$auditLastCmaas = $null
if (-not $SkipE2E) {
    Write-Host "`n===== 3. 密态 E2E（网关 :/v1/infer） =====" -ForegroundColor Cyan
    $send = {
        param([string]$prompt)
        $json = '{"model":"mock","engine_type":"cmaas","messages":[{"role":"user","content":"' + $prompt + '"}]}'
        return Exec "$Gateway/v1/infer" 'POST' $json @() 180
    }
    # 预热：Envoy 并发 worker 各持一份插件会话，TEE 重启/换版后每条 503 触发一次重握手
    $streak = 0; $warm = -1
    for ($i = 1; $i -le $WarmMaxAttempts; $i++) {
        $r = & $send "会话预热 $i"
        $e2eCodes += $r.Code
        if ($r.Code -eq 200) { $streak++ } else { $streak = 0 }
        if ($streak -ge 3) { $warm = $i; break }
    }
    $warmFails = ($e2eCodes | Where-Object { $_ -eq 503 }).Count
    Record 'E0' '会话预热收敛（连续 3 次 200）' ($warm -gt 0) `
        "第 $warm 次收敛；预热期 503=$warmFails（TEE 重启后每 worker 一条，属已知特性）"

    $roundCodes = @()
    for ($i = 1; $i -le $Rounds; $i++) {
        $r = & $send "第 $i 轮：用一句话说明机密计算的价值"
        $roundCodes += $r.Code
        $sb = New-Object System.Text.StringBuilder
        foreach ($m in [regex]::Matches($r.Body, '"content":"((?:[^"\\]|\\.)*)"')) { [void]$sb.Append($m.Groups[1].Value) }
        if ($i -eq $Rounds) { $plainText = $sb.ToString() }
    }
    Record 'E1' "密态推理 $Rounds 轮全部 200" (($roundCodes | Where-Object { $_ -ne 200 }).Count -eq 0) "codes=$($roundCodes -join ',')"
    # SSE 结构断言以单独一轮响应为准
    $last = & $send 'SSE 结构断言轮'
    $sseOk = ($last.Body -match 'finish_reason":"stop"') -and ($last.Body -match 'data: \[DONE\]')
    Record 'E2' '标准 SSE 结构（finish_reason=stop + [DONE]）' $sseOk
    Record 'E3' '解密明文非空（段① 信封往返成功）' ($plainText -ne '') `
        $(if ($plainText) { $plainText.Substring(0, [Math]::Min(60, $plainText.Length)) } else { '' })

    $audit = Exec "$Tee/audit" 'GET' '' $adminHeaders 30
    $evts = @()
    if ($audit.Code -eq 200) { try { $evts = $audit.Body | ConvertFrom-Json } catch { $evts = @() } }
    $auditLastInfer = $evts | Where-Object { $_.action -eq 'infer' } | Select-Object -Last 1
    $auditLastCmaas = $evts | Where-Object { $_.action -eq 'cmaas_attest' } | Select-Object -Last 1
    Record 'E4' '审计：infer result=ok（计 tokens）' ($null -ne $auditLastInfer -and $auditLastInfer.result -eq 'ok') `
        "code=$($audit.Code) tokens_out=$($auditLastInfer.tokens_out)"
    Record 'E5' '审计：cmaas_attest（上游证明回执）' ($null -ne $auditLastCmaas -and $auditLastCmaas.result -eq 'ok') `
        $(if ($auditLastCmaas) { "payload_hash=$($auditLastCmaas.payload_hash.Substring(0,8))" } else { '' })
}

# ---------- 4. 性能采集（TTFT / 总时长 / 吞吐） ----------
$perf = $null
if (-not $SkipPerf) {
    Write-Host "`n===== 4. 性能采集 =====" -ForegroundColor Cyan
    # 用 curl -w 取时延：time_starttransfer = 首字节到达（SSE 首帧 ≈ TTFT）。
    # 不用 .NET 流读取：HttpWebRequest 会把整体 SSE 缓冲后一次返回，测出 0ms 的假值。
    $perfReq = "$env:TEMP\tee-vm-verify-perf.json"
    $perfResp = "$env:TEMP\tee-vm-verify-perf.out"
    $samples = @()
    for ($i = 1; $i -le [Math]::Max($Rounds, 3); $i++) {
        # 每轮问题唯一化：tee 侧语义缓存命中会让时延塌成常数（测不到真实生成耗时）
        $uniq = '{"model":"mock","engine_type":"cmaas","messages":[{"role":"user","content":"用一句话说明零知识证明（第 ' + $i + ' 次采样）"}]}'
        [System.IO.File]::WriteAllText($perfReq, $uniq, (New-Object System.Text.UTF8Encoding($false)))
        $w = curl.exe -s -m 180 -o $perfResp -w '%{time_starttransfer},%{time_total}' -X POST "$Gateway/v1/infer" `
            -H 'Content-Type: application/json' --data-binary "@$perfReq" 2>$null
        $parts = "$w".Trim() -split ','
        if ($parts.Count -ne 2) { continue }
        $body = if (Test-Path $perfResp) { [System.IO.File]::ReadAllText($perfResp) } else { '' }
        $sb = New-Object System.Text.StringBuilder
        foreach ($m in [regex]::Matches($body, '"content":"((?:[^"\\]|\\.)*)"')) { [void]$sb.Append($m.Groups[1].Value) }
        $samples += [pscustomobject]@{
            ttft_ms  = [Math]::Round([double]$parts[0] * 1000, 1)
            total_ms = [Math]::Round([double]$parts[1] * 1000, 1)
            chars    = $sb.ToString().Length
        }
    }
    function Median($arr) { $s = @($arr | Sort-Object); if ($s.Count -eq 0) { return -1 }; return $s[[int][Math]::Floor($s.Count / 2)] }
    $ttftMed = Median ($samples | ForEach-Object { $_.ttft_ms })
    $totalMed = Median ($samples | ForEach-Object { $_.total_ms })
    $genMs = [Math]::Max($totalMed - $ttftMed, 1)
    $charsMed = Median ($samples | ForEach-Object { $_.chars })
    $perf = [pscustomobject]@{
        samples          = $samples.Count
        ttft_ms_median   = $ttftMed
        total_ms_median  = $totalMed
        gen_ms_median    = $genMs
        chars_median     = $charsMed
        char_per_sec     = [Math]::Round(($charsMed * 1000.0 / $genMs), 1)
        tokens_out       = $(if ($auditLastInfer) { $auditLastInfer.tokens_out } else { $null })
        note             = 'time_starttransfer 为 TTFB（SSE 首帧）近似 TTFT；chars/s 为字符口径，token 口径需 tee -tokenizer'
    }
    Record 'F1' 'TTFT 可测（首字节延迟 > 0）' ($ttftMed -gt 0) "ttft 中位=$ttftMed ms（$($samples.Count) 次采样）"
    Record 'F2' '端到端时长可测' ($totalMed -gt 0) "total 中位=$totalMed ms；生成段中位=$genMs ms"
    Record 'F3' '吞吐可估算（字符/秒，供跨环境对照）' ($perf.char_per_sec -gt 0) "chars/s=$($perf.char_per_sec)"
}

# ---------- 5. 报告落盘 ----------
$guest = ''
if ($GuestCheckFile -and (Test-Path $GuestCheckFile)) { $guest = [System.IO.File]::ReadAllText($GuestCheckFile) }
if ($guest) {
    Record 'R1' 'guest 侧 check-tdx-vm.sh 输出已并入报告' $true "$GuestCheckFile（$($guest.Length) 字符）"
} else {
    RecordSkip 'R1' 'guest 侧 check-tdx-vm.sh 输出已并入报告' '未提供 -GuestCheckFile（可接受；VM 内请先跑该脚本）'
}

# 注：@() 包裹——单条匹配时 Where-Object 返回标量，PS 5.1 下标量 .Count 可能为空
$pass = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
$fail = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
$skipCount = @($results | Where-Object { $_.Status -eq 'SKIP' }).Count
$report = [pscustomobject]@{
    tool          = 'tee-vm-verify.ps1'
    generated_at  = (Get-Date).ToString('o')
    target        = [pscustomobject]@{ gateway = $Gateway; tee = $Tee; expect_enclave = $ExpectEnclave; rounds = $Rounds }
    attest        = $attest
    e2e           = [pscustomobject]@{ warmup_codes = ($e2eCodes -join ','); warmup_503 = $warmFails; plaintext_head = $(if ($plainText) { $plainText.Substring(0, [Math]::Min(120, $plainText.Length)) } else { '' }) }
    perf          = $perf
    guest_check   = $guest
    results       = $results
    summary       = [pscustomobject]@{ pass = $pass; fail = $fail; skip = $skipCount }
}
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$jsonPath = Join-Path $OutDir 'tee-vm-verify-report.json'
$txtPath = Join-Path $OutDir 'tee-vm-verify-report.txt'
[System.IO.File]::WriteAllText($jsonPath, ($report | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
$lines = @()
$lines += "TEE VM 验证报告  $($report.generated_at)"
$lines += "目标: gateway=$Gateway  tee=$Tee  期望飞地=$ExpectEnclave  rounds=$Rounds"
$lines += ''
foreach ($r in $results) { $lines += ("[{0}] {1} - {2}`n        {3}" -f $r.Status, $r.ID, $r.Title, $r.Detail) }
$lines += ''
if ($perf) { $lines += ("性能: TTFT 中位={0}ms  总时长中位={1}ms  生成段中位={2}ms  {3} 字符/秒" -f $perf.ttft_ms_median, $perf.total_ms_median, $perf.gen_ms_median, $perf.char_per_sec) }
$lines += ("汇总: PASS={0} FAIL={1} SKIP={2}" -f $pass, $fail, $skipCount)
[System.IO.File]::WriteAllText($txtPath, ($lines -join "`r`n"), (New-Object System.Text.UTF8Encoding($true)))

Write-Host "`n===== 汇总 =====" -ForegroundColor Cyan
Write-Host "PASS=$pass FAIL=$fail SKIP=$skipCount" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host "报告: $txtPath"
Write-Host "      $jsonPath"
if ($fail -gt 0) { exit 1 }
exit 0
