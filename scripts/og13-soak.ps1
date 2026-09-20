# og13-soak.ps1 — OG-13 浸泡 harness 编排脚本
#
# 作用：启动 L2 stub → 按网格跑 Go soak test → 收集 CSV → 打印摘要表
#
# 用法（在仓库根目录执行）：
#   powershell -File scripts\og13-soak.ps1 -Profile cpu
#   powershell -File scripts\og13-soak.ps1 -Profile gpu -Blocking
#   powershell -File scripts\og13-soak.ps1 -Profile gpu -MultiRequest
#
# 两种模式：
#   默认（单请求流式）：λ×c 网格，产出降级率 / 队列深度 / 降级原因分解 / L2 占比
#   -MultiRequest（多请求并发）：N 网格，产出首帧延迟增量 P50/P99（闸门主判据）
#     与受影响请求占比（OG-13 验收要求）；强制阻塞形态
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

    [switch]$Blocking,       # 单请求模式：是否阻塞预演（测首帧延迟增量）；默认 shadow 零影响
    [switch]$MultiRequest,   # 多请求并发模式（强制 blocking=true）
    [int]$L2Port = 19099,
    [string]$OutputDir = (Join-Path $PWD "og13-results"),

    # 画像参数覆盖（G-1b 真机回填用，OG-13 §5.5.4 回填路径第 1 步）；
    # 留空则取 Profile 默认值（cpu=2800/4500，gpu=200/500）。
    [int]$MedianMs = 0,
    [int]$P99Ms = 0,
    # 并发度 c 网格覆盖：逗号分隔整数，如 "2,4,8,16"；留空用 Profile 默认
    [string]$Concurrences = "",
    # λ 网格覆盖：逗号分隔（如 "0.5,1,2,3"）；留空用 Profile 默认（§5.5.1 全网格）
    [string]$Lambdas = ""
)

$ErrorActionPreference = "Stop"

# G-1b 回填参数副本（必须）：PowerShell 变量名不区分大小写，参数 $MedianMs/$P99Ms/
# $Concurrences/$Lambdas 与同名局部变量（$medianMs/$p99Ms/$lambdaGrid）是同一变量时，
# 会被 Profile 默认值赋值覆盖，且参数的类型约束（如 [string]）会作用于后续赋值
# → 覆盖参数静默失效（λ 参数与局部同名时数组会被强制转成字符串）。故先取副本，
# 且 λ 网格局部变量改名 $lambdaGrid 以避免与参数 $Lambdas 同名。
$MedianMsOverride = $MedianMs
$P99MsOverride = $P99Ms
$ConcurrencesOverride = $Concurrences
$LambdasOverride = $Lambdas

# ---- 路径 ----
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$stubPy = Join-Path $root "scripts\og13-l2-stub.py"
$teeDir = Join-Path $root "gateway\tee-infer-service"
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$modeTag = if ($MultiRequest) { "mr" } else { "sr" } # sr=单请求流式 / mr=多请求并发
$csvPath = Join-Path $OutputDir "og13-$Profile-$modeTag-$($ts).csv"

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
# 覆盖参数（G-1b 真机回填用；读副本，见上方"参数副本"注释）
if ($MedianMsOverride -gt 0) { $medianMs = $MedianMsOverride }
if ($P99MsOverride -gt 0)   { $p99Ms    = $P99MsOverride }
if ($ConcurrencesOverride) {
    $concurrencies = $ConcurrencesOverride -split "," | ForEach-Object { [int]$_.Trim() } | Where-Object { $_ -gt 0 }
    if (-not $concurrencies) { Write-Warning "-Concurrences 解析为空，使用 Profile 默认"; $concurrencies = $concurrencies }
}
# E[S] 重算（对数正态均值 = exp(μ+σ²/2)，μ=ln(median), σ=(ln(p99)-μ)/2.3263）
$mu  = [math]::Log($medianMs / 1000.0)
$sig = ([math]::Log($p99Ms / 1000.0) - $mu) / 2.3263478740408408
$expServiceS = [math]::Exp($mu + $sig * $sig / 2.0)
$lambdaGrid = @(0.25, 0.5, 1, 1.5, 2, 3, 5, 8)
# λ 网格覆盖（G-1b 精简网格用；实时仿真下 λ 网格直接决定时长）
if ($LambdasOverride) {
    $lambdaGrid = @($LambdasOverride.Split(",") | ForEach-Object { [double]$_.Trim() } | Where-Object { $_ -gt 0 })
    if (-not $lambdaGrid) { Write-Warning "-Lambdas 解析为空，使用 Profile 默认"; $lambdaGrid = @(0.25, 0.5, 1, 1.5, 2, 3, 5, 8) }
}
# 多请求 N 网格：GPU 扩到 64 以找容量拐点（P99 样本量=N，N≤16 时 P99≈max）；
# CPU 保持 5 格（median 2.8s 首帧必破 800ms，只做趋势对照，不追拐点）
$mrRequests = if ($Profile -eq "gpu") { @(1, 2, 4, 8, 16, 32, 64) } else { @(1, 2, 4, 8, 16) }
$maxSlots = 512
$blockStr = if ($Blocking) { "true" } else { "false" }

Write-Host "=== OG-13 浸泡 harness ===" -ForegroundColor Cyan
Write-Host "  Profile:    $Profile (median=${medianMs}ms, p99=${p99Ms}ms)"
if ($MultiRequest) {
    Write-Host "  模式:       多请求并发（blocking=true，每请求 λ=1.0 句/s、30 句、c=4）"
    Write-Host "  N 网格:    $($mrRequests -join ', ') 路并发请求"
}
else {
    Write-Host "  模式:       单请求流式"
    Write-Host "  Blocking:   $Blocking ($(if ($Blocking) { "阻塞预演" } else { "shadow 零影响" }))"
    Write-Host "  λ 网格:    $($lambdaGrid -join ', ') 句/s"
    Write-Host "  c 网格:    $($concurrencies -join ', ')"
    Write-Host "  每格句数:   $Sentences (预热 $Warmup)"
}
Write-Host "  种子:      $Seed"
Write-Host "  输出:      $csvPath"
Write-Host ""

# ---- 启动 L2 stub ----
Write-Host "[1/3] 启动 L2 stub (port=$L2Port)..." -ForegroundColor Cyan
$stubOut = Join-Path $env:TEMP "og13-l2stub-out.txt"
$stubErr = Join-Path $env:TEMP "og13-l2stub-err.txt"
# G-1b 回填（§5.5.4 第 1 步）：-MedianMs/-P99Ms 覆盖时 stub 必须同样用真机画像
# （--profile custom 才吃 --median-ms/--p99-ms），否则网格实测仍按 Profile 默认延迟，
# 与摘要表的 E[S] 口径不一致。
$stubProfileArgs = if ($MedianMsOverride -gt 0 -and $P99MsOverride -gt 0) {
    @("--profile", "custom", "--median-ms", "$medianMs", "--p99-ms", "$p99Ms")
} else {
    @("--profile", $Profile)
}
$stubProc = Start-Process python -ArgumentList (@(
    "-u", $stubPy,
    "--port", $L2Port,
    "--hit-rate", "0.05",
    "--seed", $Seed
) + $stubProfileArgs) -PassThru -NoNewWindow -RedirectStandardOutput $stubOut -RedirectStandardError $stubErr -WorkingDirectory $root

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

# ---- 网格定义（两种模式）----
# 单请求流式（默认）：λ×c 网格，产出降级率/队列深度/降级原因分解。
# 多请求并发（-MultiRequest）：N 网格，每请求 λ 与句数固定；强制阻塞形态，
#   产出首帧延迟增量 P50/P99（闸门主判据）与受影响请求占比（OG-13 验收要求）。
$cells = @()
if ($MultiRequest) {
    $blockStr = "true" # 非阻塞下首帧延迟增量恒 ≈ 0，闸门判定无意义
    # 锚定正则（^...$）：避免 -run 以子串匹配同时命中另一模式的测试函数
    $testName = '^TestCascadeSoakMultiRequest$'
    $resultTag = "SOAK_MR_RESULT"
    $mrLambda = 1.0        # 每请求句到达速率（句/s）
    $mrSentences = 30      # 每请求句数
    $mrConcurrency = 4     # 每请求 P-CONCURRENCY
    foreach ($n in $mrRequests) {
        $cells += [PSCustomObject]@{
            Label = "N=$n"
            Req   = $n
            Env   = @{
                SOAK_REQUESTS    = "$n"
                SOAK_LAMBDA      = "$mrLambda"
                SOAK_CONCURRENCY = "$mrConcurrency"
                SOAK_SENTENCES   = "$mrSentences"
            }
        }
    }
    $csvHeader = "profile,requests,lambda_per_req,concurrency,blocking,sentences_per_req,first_frame_p50_ms,first_frame_p99_ms,first_frame_max_ms,affected_req_ratio,failclosed_ratio,l2_call_ratio,l2_calls_total,l2_throughput_per_sec,would_reject_top,erlang_b_per_req_pct"
}
else {
    # 锚定正则：避免同时命中 TestCascadeSoakMultiRequest（-run 为子串匹配）
    $testName = '^TestCascadeSoak$'
    $resultTag = "SOAK_RESULT"
    foreach ($c in $concurrencies) {
        foreach ($lam in $lambdaGrid) {
            $cells += [PSCustomObject]@{
                Label  = "c=$c  λ=$lam"
                C      = $c
                Lambda = $lam
                Env    = @{
                    SOAK_CONCURRENCY = "$c"
                    SOAK_LAMBDA      = "$lam"
                    SOAK_SENTENCES   = "$Sentences"
                    SOAK_WARMUP      = "$Warmup"
                }
            }
        }
    }
    $csvHeader = "profile,lambda,concurrency,blocking,sentences,first_latency_ms,throughput_sent_per_sec,queue_depth_p50,queue_depth_p99,failclosed_ratio,l2_call_ratio,l2_timeout_ratio,l2_unavailable_ratio,l2_bad_conf_ratio,l2_unmapped_ratio,erlang_b_pct"
}
$total = $cells.Count
Set-Content -Path $csvPath -Value $csvHeader -Encoding UTF8

# ---- 跑网格 ----
Write-Host ""
Write-Host "[2/3] 浸泡网格（$total 格，$testName）..." -ForegroundColor Cyan

$idx = 0
$results = @()

foreach ($cell in $cells) {
    $idx++
    Write-Host "  [$idx/$total] $($cell.Label)  " -NoNewline

    # 公共环境
    $env:SPIKE_SOAK = "1"
    $env:L2_URL = "http://127.0.0.1:$L2Port/"
    $env:L2_TIMEOUT = $l2Timeout
    $env:SOAK_PROFILE = $Profile
    $env:SOAK_MAX_SLOTS = "$maxSlots"
    $env:SOAK_BLOCKING = $blockStr
    $env:SOAK_SEED = "$Seed"
    $env:SOAK_EXP_SERVICE_S = "$expServiceS"
    # 格特有环境
    foreach ($k in $cell.Env.Keys) { Set-Item -Path "Env:\$k" -Value $cell.Env[$k] }

    # 注意：go test 会输出编译摘要到 stderr，PS 5.1 会把
    # NativeCommandError 当错误；这里临时放宽 ErrorAction。
    # -timeout：低 λ 档单格耗时可达 10 分钟以上（句数/λ），必须放宽默认 10m。
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    Push-Location $teeDir
    try {
        $out = go test -mod=mod -timeout 30m -run $testName -count=1 2>&1
    } finally {
        Pop-Location
        $ErrorActionPreference = $prevEAP
    }

    # 清理环境
    foreach ($k in @("SPIKE_SOAK", "L2_URL", "L2_TIMEOUT", "SOAK_PROFILE", "SOAK_CONCURRENCY",
            "SOAK_MAX_SLOTS", "SOAK_BLOCKING", "SOAK_LAMBDA", "SOAK_SENTENCES", "SOAK_WARMUP",
            "SOAK_SEED", "SOAK_EXP_SERVICE_S", "SOAK_REQUESTS")) {
        Remove-Item "Env:\$k" -ErrorAction SilentlyContinue
    }

    # 提取结果行（去掉前缀，对齐 CSV 表头）
    $resultLine = ($out | Where-Object { $_ -match "^$resultTag," })
    if (-not $resultLine) {
        Write-Host "FAIL" -ForegroundColor Red
        Write-Host ($out -join "`n") -ForegroundColor DarkRed
        continue
    }
    $dataLine = $resultLine -replace "^$resultTag,", ""

    # 追加 CSV
    Add-Content -Path $csvPath -Value $dataLine -Encoding UTF8

    # 解析关键列用于摘要
    $cols = $dataLine -split ","
    if ($MultiRequest) {
        # 0:profile 1:requests 2:lambda_per_req 3:concurrency 4:blocking 5:sentences_per_req
        # 6:frameP50 7:frameP99 8:frameMax 9:affected 10:fc 11:l2ratio 12:l2calls 13:l2tput
        # 14:would_reject_top 15:erlang_b_per_req_pct
        $results += [PSCustomObject]@{
            req       = $cell.Req
            p50       = [double]$cols[6]
            p99       = [double]$cols[7]
            max       = [double]$cols[8]
            affected  = [double]$cols[9]
            fc_pct    = [double]$cols[10] * 100
            l2_tput   = [double]$cols[13]
            top       = $cols[14]
            erl_b_pct = [double]$cols[15]
        }
        Write-Host ("frameP50={0,7:0.0}ms  P99={1,7:0.0}ms  max={2,7:0.0}ms  affected={3,6:0.0}%  fc={4,5:0.00}%  L2tput={5,6:0.00}/s" -f `
                [double]$cols[6], [double]$cols[7], [double]$cols[8], ([double]$cols[9] * 100), ([double]$cols[10] * 100), [double]$cols[13])
    }
    else {
        # 0:profile 1:lambda 2:concurrency 3:blocking 4:sentences
        # 5:first_latency_ms 6:throughput 7:qP50 8:qP99 9:fc_ratio 10:l2_ratio
        # 11:timeout 12:unavail 13:bad_conf 14:unmapped 15:erlang_b_pct
        $firstMs = [double]$cols[5]
        $tput = [double]$cols[6]
        $qP99 = [double]$cols[8]
        $fcRatio = [double]$cols[9]
        $erlPct = [double]$cols[15]

        $results += [PSCustomObject]@{
            c         = $cell.C
            lambda    = $cell.Lambda
            first_ms  = $firstMs
            tput      = $tput
            q_p99     = $qP99
            fc_pct    = $fcRatio * 100
            erl_b_pct = $erlPct
        }

        Write-Host ("first={0,6:0.0}ms  tput={1,5:0.00}  qP99={2,3:0.0}  fc={3,5:0.00}% (ErlB={4,5:0.00}%)" -f `
                $firstMs, $tput, $qP99, ($fcRatio * 100), $erlPct)
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
if ($MultiRequest) {
    Write-Host "=== 摘要表（$Profile / 多请求并发 / blocking=true）===" -ForegroundColor Cyan
    Write-Host ("{0,4}  {1,10}  {2,10}  {3,10}  {4,9}  {5,9}  {6,11}  {7,10}  {8}" -f `
        "N", "frameP50", "frameP99", "frameMax", "affect%", "fc_实测%", "L2tput/s", "fc_ErlB%", "命中分布(top5)")
    Write-Host ("-" * 132)

    foreach ($r in ($results | Sort-Object req)) {
        Write-Host ("{0,4}  {1,10:0.0}  {2,10:0.0}  {3,10:0.0}  {4,9:0.00}  {5,9:0.00}  {6,11:0.00}  {7,10:0.00}  {8}" -f `
            $r.req, $r.p50, $r.p99, $r.max, ($r.affected * 100), $r.fc_pct, $r.l2_tput, $r.erl_b_pct, $r.top)
    }
    Write-Host ""
    Write-Host "  首帧延迟增量单位 ms（闸门：P99 ≤ 800ms）；affect% = 至少一句 P-DEGRADE 的请求占比" -ForegroundColor DarkGray
}
else {
    Write-Host "=== 摘要表（$Profile / blocking=$Blocking）===" -ForegroundColor Cyan
    Write-Host ("{0,3}  {1,6}  {2,8}  {3,8}  {4,6}  {5,10}  {6,10}" -f `
        "c", "λ", "first_ms", "tput_s/s", "qP99", "fc_实测%", "fc_ErlB%")
    Write-Host ("-" * 70)

    foreach ($c in $concurrencies) {
        foreach ($lam in $lambdaGrid) {
            $r = $results | Where-Object { $_.c -eq $c -and $_.lambda -eq $lam }
            if ($r) {
                Write-Host ("{0,3}  {1,6}  {2,8:0.0}  {3,8:0.00}  {4,6:0.0}  {5,10:0.000}  {6,10:0.000}" -f `
                    $r.c, $r.lambda, $r.first_ms, $r.tput, $r.q_p99, $r.fc_pct, $r.erl_b_pct)
            }
        }
        Write-Host ""
    }
}

Write-Host ""
Write-Host "原始 CSV: $csvPath" -ForegroundColor Green
Write-Host "完成。" -ForegroundColor Green
