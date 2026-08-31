# setup-env.ps1 - OTP-Mask 安全 AI 网关一键环境搭建（Windows）
#
# 流程：工具检查（缺则安装）→ GOPROXY → 全量构建（含 wasm）→ 启动容器 → 验证套件
#
# 用法：
#   powershell -File scripts/setup-env.ps1               # 完整流程（构建+启动+验证）
#   powershell -File scripts/setup-env.ps1 -SkipVerify   # 跳过验证套件（仅构建+启动）
#   powershell -File scripts/setup-env.ps1 -WithK8sTools # 额外检查 helm/kubectl/kind
#
# 依赖：Windows 10/11 + winget（自动安装 Git/Docker 需重启后生效）

param(
    [switch]$SkipVerify,
    [switch]$WithK8sTools
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$go = $env:GO_BIN
if (-not $go) {
    $g = Get-Command go -ErrorAction SilentlyContinue
    if ($g) { $go = $g.Source } else { $go = 'C:\Program Files\Go\bin\go.exe' }
}
$results = @

function Check-Tool {
    param([string]$Name, [string]$Probe, [string]$WingetId)
    $found = $false
    try {
        $v = & cmd /c $Probe 2>$null
        if ($LASTEXITCODE -eq 0) { $found = $true }
    } catch { }
    if ($found) {
        $script:results += "[PASS] $Name 已安装"
        Write-Host "[PASS] $Name 已安装"
    } else {
        if ($WingetId) {
            Write-Host "[INFO] $Name 缺失，尝试 winget 安装 $WingetId（安装后可能需要重启终端）..."
            winget install --id $WingetId -e --accept-source-agreements --accept-package-agreements | Out-Null
            $script:results += "[INFO] $Name 已尝试安装（winget）"
        } else {
            $script:results += "[FAIL] $Name 缺失（无 winget 源，请手动安装）"
            Write-Host "[FAIL] $Name 缺失（无 winget 源，请手动安装）" -ForegroundColor Red
        }
    }
}

Write-Host "===== OTP-Mask 环境搭建 =====" -ForegroundColor Cyan
Push-Location $root

# 1. 工具检查
Write-Host "`n[1/6] 工具检查" -ForegroundColor Yellow
Check-Tool 'Git' { git --version } 'Git.Git'
Check-Tool 'Docker' { docker --version } 'Docker.DockerDesktop'
if (Test-Path $go) {
    $script:results += '[PASS] Go 已安装'
    Write-Host '[PASS] Go 已安装'
} else {
    Write-Host '[FAIL] Go 缺失（请从 https://go.dev/dl 安装 Go 1.24+）' -ForegroundColor Red
}
Check-Tool 'Python' { python --version } 'Python.Python.3.10'
if ($WithK8sTools) {
    Check-Tool 'kubectl' { kubectl version --client } 'Kubernetes.kubectl'
    Check-Tool 'helm' { helm version --short } $null
    Check-Tool 'kind' { kind version } $null
}

# 2. GOPROXY（国内网络）
Write-Host "`n[2/6] Go 环境" -ForegroundColor Yellow
& $go env -w GOPROXY=https://goproxy.cn,direct
Write-Host "[PASS] GOPROXY=https://goproxy.cn,direct"

# 3. 全量构建（含 wasm 插件）
Write-Host "`n[3/6] 全量构建" -ForegroundColor Yellow
& $go build ./... *> $null
if ($LASTEXITCODE -ne 0) { throw 'go build 失败' }
$env:GOOS = 'wasip1'; $env:GOARCH = 'wasm'
& $go build -buildmode=c-shared -o gateway/wasm/otpmask-plugin/main.wasm ./gateway/wasm/otpmask-plugin *> $null
if ($LASTEXITCODE -ne 0) { throw 'wasm 构建失败' }
Write-Host '[PASS] Go 全量构建 + wasm 插件构建完成'

# 4. Python 依赖说明（无第三方依赖，仅标准库）
Write-Host "`n[4/6] Python 检查" -ForegroundColor Yellow
python -c "import sys; sys.path.insert(0, r'protocol/python'); import otpmask_protocol; print('[PASS] otpmask_protocol 可导入')"

# 5. 启动容器（Docker Compose）
Write-Host "`n[5/6] 启动容器" -ForegroundColor Yellow
Push-Location (Join-Path $root 'gateway\wasm\otpmask-plugin')
docker compose up -d --build | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'docker compose up 失败' }
Pop-Location
Start-Sleep -Seconds 6
Write-Host '[PASS] 容器已启动（网关 10000 / embedding 18080 / tee-infer 19090）'

# 6. 验证套件
if ($SkipVerify) {
    Write-Host "`n[6/6] 跳过验证（-SkipVerify）"
} else {
    Write-Host "`n[6/6] 验证套件" -ForegroundColor Yellow
    & powershell -NoProfile -File scripts/verify-all.ps1 *> $null
    if ($LASTEXITCODE -ne 0) { Write-Host '[FAIL] 验证套件未全过' -ForegroundColor Red } else { Write-Host '[PASS] 验证套件 ALL PASSED' }
}

Pop-Location

Write-Host "`n===== 完成 =====" -ForegroundColor Cyan
Write-Host '访问入口：'
Write-Host '  推理（SSE）: http://127.0.0.1:10000/infer'
Write-Host '  治理/指标:   http://127.0.0.1:19090/usage | /audit/verify | /metrics'
Write-Host '  （GPU 环境接真实 vLLM：scripts/vllm-up.ps1 -Mode Gpu）'
