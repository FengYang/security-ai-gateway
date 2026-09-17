# og13-soak.ps1 — OG-13 B2 浸泡 harness 编排脚本
#
# 作用：启动 L2 stub → 按 λ×c 网格跑 Go soak test → 收集 CSV → 打印摘要表
#
# 用法（在仓库根目录执行）：
#   powershell -File scripts\og13-soak.ps1 -Profile cpu
#   powershell -File scripts\og13-soak.ps1 -Profile gpu -Blocking
#
# 输出：
#   .\og13-results\og13-{profile}-{date}.csv   原始 CSV
#   控制台打印摘要表（含 Erlang-B 对照）
#
# 前置：Python 3、Go 工具链可用；当前目录为仓库根。

param(
    [ValidateSet("cpu","gpu")]
    [string]$Profile = "cpu",

    [int]$Sentences = 300,
    [int]$Warmup = 30,
    [int]$Seed = 20260917,

    [switch]$Blocking,    # 是否阻塞预演（测首帧延迟增量）；默认 shadow 零影响
    [int]$L2Port = 19099,
    [string]$OutputDir = (Join-Path $PWD "og13-results")
)

$ErrorActionPreference = "Stop"

# ---- 路径 ----
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$stubPy = Join-Path $root "scripts\og13-l2-stub.py"
$teeDir = Join-Path $root "gateway\tee-infer-service"
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$csvPath = Join-Path $OutputDir "og13-$Profile-$($ts).csv"

# ---- Profile 参数 ----
if ($Profile -eq "cpu") {
    $medianMs = 2800
    $p99Ms = 4500
    $concurrencies = @(1, 2, 4, 8)
    $expServiceS = 2.8   # 近似用 median；对数正态均值略大，报告里注明
    $l2Timeout = "6s"    # CPU 形态给宽一点
}
else {
    $medianMs = 200
    $p99Ms = 500
    $concurrencies = @(1, 2, 4)
    $expServiceS = 0.2
    $l2Timeout = "2s"
}
$lambdas = @(0.25, 0.5, 1, 1.5, 2, 3, 5, 8)
$maxSlots = 512
$blockStr = if ($Blocking) { "true" } else { "false" }

Write-Host "=== OG-13 浸泡 harness ===" -ForegroundColor Cyan
Write-Host "  Profile:    $Profile (median=${medianMs}ms, p99=${p99Ms}ms)"
Write-Host "  Blocking:   $Blocking ($(if ($Blocking) { "阻塞预演" } else { "shadow 零影响" }))"
Write-Host "  λ 网格:    $($lambdas -join ', ') 句/s"
Write-Host "  c 网格:    $($concurrencies -join ', ')"
Write-Host "  每格句数:   $Sentences (预热 $Warmup)"
Write-Host "  种子:      $Seed"
Write-Host "  输出:      $csvPath"
Write-Host ""

# ---- 启动 L2 stub ----
Write-Host "[1/3] 启动 L2 stub (port=$L2Port)..." -ForegroundColor Cyan
$stubOut = Join-Path $env:TEMP "og13-l2stub-out.txt"
$stubErr = Join-Path $env:TEMP "og13-l2stub-err.txt"
$stubProc = Start-Process python -ArgumentList @(
    "-u", $stubPy,
    "--profile", $Profile,
    "--port", $L2Port,
    "--hit-rate", "0.05",
    "--seed", $Seed
) -PassThru -NoNewWindow -RedirectStandardOutput $stubOut -RedirectStandardError $stubErr -WorkingDirectory $root

# 等 stub 就绪
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$L2Port/healthz" -Method Get -TimeoutSec 2 -UseBasicParsing
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch {}
    Start-Sleep -Milliseconds 200
}
if (-not $ready) {
    Write-Host "  FAIL: L2 stub 启动失败" -ForegroundColor Red
    Get-Content $stubErr -ErrorAction SilentlyContinue | Write-Host
    exit 1
}
Write-Host "  L2 stub 就绪 (PID=$($stubProc.Id))" -ForegroundColor Green

# ---- CSV 表头 ----
$csvHeader = "profile,lambda,concurrency,blocking,sentences,first_latency_ms,throughput_sent_per_sec,queue_depth_p50,queue_depth_p99,failclosed_ratio,l2_call_ratio,l2_timeout_ratio,l2_unavailable_ratio,l2_bad_conf_ratio,l2_unmapped_ratio,erlang_b_pct"
Set-Content -Path $csvPath -Value $csvHeader -Encoding UTF8

# ---- 跑网格 ----
Write-Host ""
Write-Host "[2/3] 浸泡网格 ($($lambdas.Count) × $($concurrencies.Count) = $($lambdas.Count * $concurrencies.Count) 组)..." -ForegroundColor Cyan

$total = $lambdas.Count * $concurrencies.Count
$idx = 0
$results = @()

foreach ($c in $concurrencies) {
    foreach ($lam in $lambdas) {
        $idx++
        Write-Host "  [$idx/$total] c=$c  λ=$lam  " -NoNewline

        $env:SPIKE_SOAK = "1"
        $env:L2_URL = "http://127.0.0.1:$L2Port/"
        $env:L2_TIMEOUT = $l2Timeout
        $env:SOAK_PROFILE = $Profile
        $env:SOAK_CONCURRENCY = "$c"
        $env:SOAK_MAX_SLOTS = "$maxSlots"
        $env:SOAK_BLOCKING = $blockStr
        $env:SOAK_LAMBDA = "$lam"
        $env:SOAK_SENTENCES = "$Sentences"
        $env:SOAK_WARMUP = "$Warmup"
        $env:SOAK_SEED = "$Seed"
        $env:SOAK_EXP_SERVICE_S = "$expServiceS"

        # 注意：go test 会输出编译摘要到 stderr，PS 5.1 会把
        # NativeCommandError 当错误；这里临时放宽 ErrorAction
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $out = go test -mod=mod -run TestCascadeSoak -count=1 2>&1
        $ErrorActionPreference = $prevEAP

        # 清理环境
        Remove-Item Env:\SPIKE_SOAK -ErrorAction SilentlyContinue
        Remove-Item Env:\L2_URL -ErrorAction SilentlyContinue
        Remove-Item Env:\L2_TIMEOUT -ErrorAction SilentlyContinue
        Remove-Item Env:\SOAK_PROFILE -ErrorAction SilentlyContinue
        Remove-Item Env:\SOAK_CONCURRENCY -ErrorAction SilentlyContinue
        Remove-Item Env:\SOAK_MAX_SLOTS -ErrorAction SilentlyContinue
        Remove-Item Env:\SOAK_BLOCKING -ErrorAction SilentlyContinue
        Remove-Item Env:\SOAK_LAMBDA -ErrorAction SilentlyContinue
        Remove-Item Env:\SOAK_SENTENCES -ErrorAction SilentlyContinue
        Remove-Item Env:\SOAK_WARMUP -ErrorAction SilentlyContinue
        Remove-Item Env:\SOAK_SEED -ErrorAction SilentlyContinue
        Remove-Item Env:\SOAK_EXP_SERVICE_S -ErrorAction SilentlyContinue

        # 提取 SOAK_RESULT 行（去掉前缀，对齐 CSV 表头 16 列）
        $resultLine = ($out | Where-Object { $_ -match "^SOAK_RESULT," })
        if (-not $resultLine) {
            Write-Host "FAIL" -ForegroundColor Red
            Write-Host ($out -join "`n") -ForegroundColor DarkRed
            continue
        }
        $dataLine = $resultLine -replace "^SOAK_RESULT,", ""

        # 追加 CSV
        Add-Content -Path $csvPath -Value $dataLine -Encoding UTF8

        # 解析关键列用于摘要（0:profile 1:lambda 2:concurrency 3:blocking 4:sentences
        # 5:first_latency_ms 6:throughput 7:qP50 8:qP99 9:fc_ratio 10:l2_ratio
        # 11:timeout 12:unavail 13:bad_conf 14:unmapped 15:erlang_b_pct）
        $cols = $dataLine -split ","
        $firstMs = [double]$cols[5]
        $tput = [double]$cols[6]
        $qP99 = [double]$cols[8]
        $fcRatio = [double]$cols[9]
        $erlPct = [double]$cols[15]

        $results += [PSCustomObject]@{
            c = $c
            lambda = $lam
            first_ms = $firstMs
            tput = $tput
            q_p99 = $qP99
            fc_pct = $fcRatio * 100
            erl_b_pct = $erlPct
        }

        Write-Host ("first={0,6:0.0}ms  tput={1,5:0.00}  qP99={2,3:0.0}  fc={3,5:0.00}% (ErlB={4,5:0.00}%)" -f `
            $firstMs, $tput, $qP99, ($fcRatio*100), $erlPct)
    }
}

# ---- 关 stub ----
Write-Host ""
Write-Host "[3/3] 关闭 L2 stub..." -ForegroundColor Cyan
Stop-Process -Id $stubProc.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 200
Write-Host "  done" -ForegroundColor Green

# ---- 摘要表 ----
Write-Host ""
Write-Host "=== 摘要表（$Profile / blocking=$Blocking）===" -ForegroundColor Cyan
Write-Host ("{0,3}  {1,6}  {2,8}  {3,8}  {4,6}  {5,10}  {6,10}" -f `
    "c", "λ", "first_ms", "tput_s/s", "qP99", "fc_实测%", "fc_ErlB%")
Write-Host ("-" * 70)

foreach ($c in $concurrencies) {
    foreach ($lam in $lambdas) {
        $r = $results | Where-Object { $_.c -eq $c -and $_.lambda -eq $lam }
        if ($r) {
            Write-Host ("{0,3}  {1,6}  {2,8:0.0}  {3,8:0.00}  {4,6:0.0}  {5,10:0.000}  {6,10:0.000}" -f `
                $r.c, $r.lambda, $r.first_ms, $r.tput, $r.q_p99, $r.fc_pct, $r.erl_b_pct)
        }
    }
    Write-Host ""
}

Write-Host ""
Write-Host "原始 CSV: $csvPath" -ForegroundColor Green
Write-Host "完成。" -ForegroundColor Green
