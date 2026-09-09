# demo-phala-chain.ps1 - 展示环境2.0 演示/验证：Higress → tee-infer → Phala 密态推理链
#
# 自动化验证场景并打印 PASS/FAIL：
#   A. 密态文本推理闭环   Higress /v1/infer → quote 握手 + K_enc 信封 → cmaas 引擎
#                         → Phala 云密态推理 → SSE 信封增量解密 → 标准 OpenAI SSE
#                         明文（delta.content + finish_reason=stop + [DONE]）
#   B. 会话复用稳定       连续 N 个不同问题全部 200 且解密出非空明文
#                         （证明会话跨请求复用、信封计数器连续稳定）
#   C. 审计与证明回执     TEE /audit 尾部存在 infer result=ok（计 tokens）与
#                         cmaas_attest（Phala 证明回执已落审计链）
#   D. 可观测性           本次运行前后 TEE /metrics 的 engine_error 拒绝计数零增长
#   E.(可选) fail-closed   -RunFailClosed：停 tee → Higress 返回 503 → 自动重启
#                          （start-tee-infer-phala.ps1）→ 复测恢复 200
#
# 前置：tee-infer-service(:19090) 与 Higress(:8080) 已在运行
#       （embedding :18080 本链不依赖，但保持运行以对齐展示拓扑）。
# 用法：powershell -ExecutionPolicy Bypass -File scripts\demo-phala-chain.ps1 [-Rounds 3] [-RunFailClosed]
# 退出码：0 = 全部通过；1 = 存在失败（可接 CI）。
#
# 注：本脚本为 UTF-8 with BOM；含中文，勿改为无 BOM 保存（PS 5.1 按 ANSI 解析会坏语法）。

param(
    [string]$BaseUrl = 'http://127.0.0.1:8080',
    [int]$TeePort = 19090,
    [int]$Rounds = 3,
    [switch]$RunFailClosed,
    [switch]$SkipPreflight
)

$ErrorActionPreference = 'Stop'
$tee = "http://127.0.0.1:$TeePort"
$reqFile = Join-Path $env:TEMP 'demo-infer.json'
$respFile = Join-Path $env:TEMP 'demo-infer-resp.txt'

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

function Get-EngineErrorCount() {
    # 计数标签按需注册：无 engine_error 拒绝时 metrics 不输出该行 → 视为 0。
    # curl 失败（服务不可达）返回 -1（调用方识别为解析失败）。
    $raw = & curl.exe -s -m 10 "$tee/metrics" 2>$null
    if ($LASTEXITCODE -ne 0) { return -1 }
    $txt = ($raw | Out-String)
    $m = [regex]::Match($txt, 'otpmask_denies_total\{[^}]*reason="engine_error"\}\s+(\d+)')
    if ($m.Success) { return [int64]$m.Groups[1].Value }
    return 0
}

function Send-Infer([string]$prompt) {
    $json = '{"model":"mock","engine_type":"cmaas","messages":[{"role":"user","content":"' + $prompt + '"}]}'
    [System.IO.File]::WriteAllText($reqFile, $json, (New-Object System.Text.UTF8Encoding($false)))
    # 会话失效恢复期：TEE 重启后插件持旧会话，首个业务请求 503（fail-closed 不降级，
    # 插件侧触发重握手），风暴下需 2-3 请求才稳定 → 最多 4 次尝试（间隔 2s）。
    $code = ''
    for ($attempt = 0; $attempt -lt 4; $attempt++) {
        $code = & curl.exe -s -m 120 -o $respFile -w '%{http_code}' -X POST "$BaseUrl/v1/infer" `
            -H 'Content-Type: application/json' --data-binary "@$reqFile" 2>$null
        if ("$code".Trim() -ne '503') { break }
        Start-Sleep -Seconds 2
    }
    $body = ''
    if (Test-Path $respFile) { $body = [System.IO.File]::ReadAllText($respFile) }
    return [pscustomobject]@{ Code = "$code".Trim(); Body = $body }
}

# 聚合 SSE 全部 delta.content（真实流式分多块，仅取首块只剩首字，摘要无意义）
function Get-Content([string]$body) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($m in [regex]::Matches($body, '"content":"((?:[^"\\]|\\.)*)"')) {
        [void]$sb.Append($m.Groups[1].Value)
    }
    return $sb.ToString()
}

Write-Host '===== 展示环境2.0 · Phala 密态推理链演示验证 =====' -ForegroundColor Cyan
Write-Host "Higress=$BaseUrl  TEE=$tee  Rounds=$Rounds"
$failCount = 0

# ---------- 预检 ----------
if (-not $SkipPreflight) {
    Write-Host "`n[预检] 服务就绪" -ForegroundColor Yellow
    $h8080 = Test-Port 8080
    $t19090 = Test-Port $TeePort
    Check 'Higress 网关 :8080' $h8080
    Check "tee-infer-service :$TeePort" $t19090
    if (-not ($h8080 -and $t19090)) {
        Write-Host '预检失败：请先启动 Higress 与 tee-infer-service（scripts\start-tee-infer-phala.ps1）' -ForegroundColor Red
        exit 1
    }
}

# D 基线：engine_error 拒绝计数（本次运行前）
$engBase = Get-EngineErrorCount
Write-Host "`n[D 基线] TEE engine_error 拒绝计数 = $engBase" -ForegroundColor DarkGray

# ---------- A. 密态文本推理闭环 ----------
Write-Host "`n[A] 密态文本推理闭环（quote 握手 + 信封 + Phala）" -ForegroundColor Yellow
$r = Send-Infer '用一句话介绍机密计算'
$okSse = ($r.Code -eq '200') -and ($r.Body -match 'finish_reason":"stop"') -and ($r.Body -match 'data: \[DONE\]')
$content = Get-Content $r.Body
$okNonEmpty = ($content -ne '')
Check 'A1 推理 HTTP 200' ($r.Code -eq '200') "(code=$($r.Code))"
Check 'A2 标准 SSE 结构（stop+[DONE]）' $okSse
Check 'A3 解密明文非空' $okNonEmpty
if ($content) { Write-Host ("    明文摘录: " + $content.Substring(0, [Math]::Min(80, $content.Length))) -ForegroundColor DarkCyan }

# ---------- B. 会话复用稳定 ----------
Write-Host "`n[B] 会话复用（连续 $Rounds 个不同问题）" -ForegroundColor Yellow
$questions = @(
    '什么是零知识证明，一句话',
    '量子计算和经典计算的最大区别是什么，一句话',
    '7 乘以 8 等于多少'
)
for ($i = 0; $i -lt $Rounds; $i++) {
    $q = $questions[$i % $questions.Count] + "（第 $($i+1) 问）"
    $ri = Send-Infer $q
    $c = Get-Content $ri.Body
    $ok = ($ri.Code -eq '200') -and ($c -ne '')
    Check ("B$($i+1) 第 $($i+1) 问解密成功") $ok "(code=$($ri.Code))"
    if ($c) { Write-Host ("    明文: " + $c.Substring(0, [Math]::Min(60, $c.Length))) -ForegroundColor DarkCyan }
}

# ---------- C. 审计与证明回执 ----------
Write-Host "`n[C] 审计链与 Phala 证明回执" -ForegroundColor Yellow
$auditJson = & curl.exe -s -m 10 "$tee/audit" 2>$null | Out-String
$evts = @()
if ($auditJson.Trim()) {
    try { $evts = $auditJson | ConvertFrom-Json } catch { $evts = @() }
}
$lastInfer = $evts | Where-Object { $_.action -eq 'infer' } | Select-Object -Last 1
$lastCmaas = $evts | Where-Object { $_.action -eq 'cmaas_attest' } | Select-Object -Last 1
Check 'C1 审计存在 infer result=ok' ($null -ne $lastInfer -and $lastInfer.result -eq 'ok') `
    "(tokens_out=$($lastInfer.tokens_out) engine=$($lastInfer.engine_type))"
Check 'C2 审计存在 cmaas_attest（Phala 回执）' ($null -ne $lastCmaas -and $lastCmaas.result -eq 'ok')
if ($lastCmaas) { Write-Host ("    回执审计: " + $lastCmaas.result + " payload=" + $lastCmaas.payload_hash.Substring(0, 8)) -ForegroundColor DarkCyan }

# ---------- D. 指标零增长（本轮无新 engine_error） ----------
Write-Host "`n[D] 可观测性：本轮 engine_error 拒绝零增长" -ForegroundColor Yellow
$engAfter = Get-EngineErrorCount
Check 'D1 /metrics 可达且计数可读' ($engAfter -ge 0)
if ($engBase -ge 0 -and $engAfter -ge 0) {
    Check 'D2 本轮无新增 engine_error' ($engAfter -eq $engBase) "($engBase → $engAfter)"
} else {
    Check 'D2 本轮无新增 engine_error' $false '计数解析失败'
}

# ---------- E.(可选) fail-closed 演练 ----------
if ($RunFailClosed) {
    Write-Host "`n[E] fail-closed 演练（停 tee → 503 → 自动恢复）" -ForegroundColor Yellow
    $pidLine = netstat -ano | Select-String ":$TeePort" | Select-String 'LISTENING' | Select-Object -First 1
    $teePid = if ($pidLine) { (($pidLine.ToString() -split '\s+') | Where-Object { $_ -match '^\d+$' } | Select-Object -Last 1) } else { '' }
    if (-not $teePid) { Check 'E1 停止 tee-infer-service' $false '未找到进程'; exit 1 }
    Stop-Process -Id $teePid -Force
    Start-Sleep -Seconds 2
    $r503 = Send-Infer '此请求应在 fail-closed 下被拒'
    Check 'E1 停服后网关 fail-closed 503' ($r503.Code -eq '503') "(code=$($r503.Code))"
    # 自动恢复：以 Phala 注入脚本重启 tee
    Write-Host '    重启 tee-infer-service（start-tee-infer-phala.ps1）...' -ForegroundColor DarkGray
    $starter = Join-Path $PSScriptRoot 'start-tee-infer-phala.ps1'
    Start-Process powershell -ArgumentList @('-ExecutionPolicy', 'Bypass', '-File', "`"$starter`"", '-Port', "$TeePort") -WindowStyle Hidden
    $ready = $false
    foreach ($i in 1..40) {
        Start-Sleep -Seconds 1
        if (Test-Port $TeePort) { $ready = $true; break }
    }
    Check 'E2 tee-infer 恢复就绪' $ready
    if ($ready) {
        # TEE 重启后插件旧会话已失效：首个请求触发握手重建，窗口内可能 503 →
        # 带预热重试（演示场景容忍，最长约 10s）。
        Start-Sleep -Seconds 2
        $rr = $null
        for ($i = 1; $i -le 5; $i++) {
            $rr = Send-Infer '服务恢复后请再回答：用一句话介绍机密计算'
            if ($rr.Code -eq '200') { break }
            Start-Sleep -Seconds 2
        }
        $rc = if ($rr) { Get-Content $rr.Body } else { '' }
        Check 'E3 恢复后推理 200' ($null -ne $rr -and $rr.Code -eq '200') "(code=$($rr.Code))"
        Check 'E4 恢复后明文解密成功' ($rc -ne '')
        if ($rc) { Write-Host ("    明文: " + $rc.Substring(0, [Math]::Min(60, $rc.Length))) -ForegroundColor DarkCyan }
    }
}

# ---------- 汇总 ----------
Write-Host "`n===== 汇总 =====" -ForegroundColor Cyan
$pass = ($results | Where-Object { $_.Status -eq 'PASS' }).Count
$fail = ($results | Where-Object { $_.Status -eq 'FAIL' }).Count
Write-Host "PASS=$pass  FAIL=$fail" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
$results | Where-Object { $_.Status -eq 'FAIL' } | ForEach-Object { Write-Host ("  FAIL " + $_.Name + ' - ' + $_.Detail) -ForegroundColor Red }
if ($fail -gt 0) { exit 1 }
exit 0
