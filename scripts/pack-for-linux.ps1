<#
.SYNOPSIS
  把运行所需源码打包为 tar.gz，便于拷贝到 Linux 服务器部署。

.DESCRIPTION
  用 robocopy 把项目源码筛到临时目录（排除构建产物、HTML 报告、.git、
  密钥与环境文件等），再压缩为 security-ai-gateway-linux.tar.gz（Linux
  原生格式，解压最简单）。Windows 11 自带 tar，无需额外安装。

.EXAMPLE
  .\scripts\pack-for-linux.ps1            # 产出 tar.gz（推荐，Linux 端 tar -xzf）
  .\scripts\pack-for-linux.ps1 -AsZip     # 产出 zip（备用，Linux 端 unzip）
#>
param(
  [switch]$AsZip
)

$ErrorActionPreference = 'Stop'
$root = (Split-Path -Parent $PSScriptRoot)
$name = 'security-ai-gateway-linux'
$stage = Join-Path $env:TEMP $name

# Windows 自带 tar / PowerShell 自带压缩，二者皆可用
if (-not (Get-Command tar -ErrorAction SilentlyContinue) -and -not $AsZip) {
  Write-Host '[INFO] 未找到 tar，自动改用 zip（-AsZip）' -ForegroundColor Yellow
  $AsZip = $true
}

# ---- 目录级排除（robocopy /XD，支持通配符）----
$exclDirs = @(
  '.git', '.claude', '.workbuddy', '.vscode', '.idea',
  'assets', '_shared', '.trae-html-share-packages',
  'coverage',
  # 独立 vLLM 源码库（本地约 1.4GB，单独维护，.gitignore 亦排除 /vllm/）
  'vllm',
  # HTML 报告 / 方案文档（与运行无关，可在源码重新生成）
  'otp-mask-*', 'vllm-masked-inference-plan', 'confidential-ai-gateway-whitepaper'
)

# ---- 文件级排除（robocopy /XF，支持通配符）----
$exclFiles = @(
  # 构建产物
  '*.exe', '*.wasm', '*.dll', '*.so', '*.test', '*.out', 'coverage.out', 'coverage',
  # 安全敏感
  '.env', '.env.local', 'secrets.yaml', '*.key', '*.pem', '*.crt',
  # 杂项
  '*.log', '*.tmp', '*.bak', '*.zip', '*.tar.gz', '*.html', '*.png', '*.jpg', '*.swp'
)

# ---- 复制源码到临时目录 ----
Write-Host '== [1/3] 清除旧产物并筛选源码 ==' -ForegroundColor Cyan
# 先删旧产物与临时目录，避免上一版 tar.gz 被打进新包
$outFile = Join-Path $root ($name + $(if ($AsZip) { '.zip' } else { '.tar.gz' }))
if (Test-Path $outFile) { Remove-Item $outFile -Force }
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
robocopy $root $stage /E /XD $exclDirs /XF $exclFiles /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) {
  Write-Error "robocopy 失败，退出码 $LASTEXITCODE（>=8 表示复制错误）"
}

# ---- 压缩 ----
Write-Host '== [2/3] 压缩 ==' -ForegroundColor Cyan
if ($AsZip) {
  Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $outFile
} else {
  tar -czf $outFile -C $stage .
}
if ($LASTEXITCODE -ne 0) { Write-Error "压缩失败，退出码 $LASTEXITCODE" }

# ---- 汇报 ----
Write-Host '== [3/3] 完成 ==' -ForegroundColor Cyan
$mb = [math]::Round((Get-Item $outFile).Length / 1MB, 2)
Write-Host ("产物: {0}  ({1} MB)" -f $outFile, $mb) -ForegroundColor Green
$suffix = if ($AsZip) { '.zip' } else { '.tar.gz' }
Write-Host ''
Write-Host ("Linux 端解压 ({0}):" -f $suffix)
Write-Host '  mkdir -p ~/security-ai-gateway' -ForegroundColor Yellow
if ($AsZip) {
  Write-Host ("  unzip {0} -d ~/security-ai-gateway" -f ($name + $suffix)) -ForegroundColor Yellow
} else {
  Write-Host ("  tar -xzf {0} -C ~/security-ai-gateway" -f ($name + $suffix)) -ForegroundColor Yellow
}

Remove-Item $stage -Recurse -Force
Write-Host ''
Write-Host "提示: 解压后执行 bash scripts/setup-env.sh 完成环境搭建与启动（已修复函数定义语法 bug）。" -ForegroundColor DarkCyan