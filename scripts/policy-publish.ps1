<#
.SYNOPSIS
  策略/词库版本发布（S1-4 / G21 离线侧）——生成 policy/versions/ 版本快照并维护索引。

.DESCRIPTION
  职责划分（见 gateway/tee-infer-service/outputguard_policy_version.go 文件头）：
    - 本脚本负责**写入**（草稿 → 版本快照 → 索引 / 基线自举）；
    - tee-infer 运行时只做**只读**发现 / 显式引用 / 回滚（容器 readOnlyRootFilesystem，不写盘）。

  硬门禁：**没有评测记录（-BenchJson）的版本只能归档为 draft**（draft 不可被 activate）。
  这也意味着基线（baseline）必须由首次发布的评测记录自举——不预置、不猜测（避免伪造口径）。

.EXAMPLE
  # 1) 首次发布并自举基线（评测记录须来自评测跑道，如 docs/benchmark/guardrail-classifier/*.json 转换）
  ./scripts/policy-publish.ps1 -Version pv2026.09.26 -FromDir .tools/policy-draft -BenchJson .tools/bench-pv2026.09.26.json -InitBaseline

.EXAMPLE
  # 2) 归档为草稿（无评测记录：可先入库，待评测通过后再发布）
  ./scripts/policy-publish.ps1 -Version pv2026.09.27 -FromDir .tools/policy-draft

.EXAMPLE
  # 3) 发布后校验（Go 侧门禁：逐个版本复算哈希 + bench 门禁）
  go test -mod=mod ./gateway/tee-infer-service/ -run TestPolicyVersionArtifactsVerify -v
#>
[CmdletBinding()]
param(
    # 目标版本号（须与 -FromDir/manifest.json 的 policy_version 一致）
    [Parameter(Mandatory = $true)][string]$Version,

    # 策略快照来源目录（须含 manifest.json；不得包含 versions/ 子目录）
    [Parameter(Mandatory = $true)][string]$FromDir,

    # policy 根目录（默认与镜像内一致）
    [string]$PolicyDir = "gateway/tee-infer-service/policy",

    # 评测记录 JSON（versions/<v>/bench.json 的内容；无则只能 draft）
    [string]$BenchJson = "",

    # 首次发布的基线自举：把本次评测记录写入 index.baseline（须同时提供 -BenchJson）
    [switch]$InitBaseline,

    # 归档说明（进 index 条目，便于追溯）
    [string]$Note = ""
)

$ErrorActionPreference = "Stop"

function Fail([string]$msg) {
    Write-Host "❌ $msg" -ForegroundColor Red
    exit 1
}

# ---- 1. 校验来源目录与 manifest 自洽 ----

$srcManifest = Join-Path $FromDir "manifest.json"
if (-not (Test-Path $srcManifest)) {
    Fail "来源目录缺少 manifest.json：$srcManifest"
}
if (Test-Path (Join-Path $FromDir "versions")) {
    Fail "来源目录不得包含 versions/ 子目录（版本库由本脚本维护）：$FromDir"
}

$mf = Get-Content $srcManifest -Raw | ConvertFrom-Json
if ($mf.policy_version -ne $Version) {
    Fail "manifest.policy_version=$($mf.policy_version) 与 -Version=$Version 不一致（版本号须单一事实源）"
}
if (-not $mf.files -or $mf.files.Count -eq 0) {
    Fail "manifest.files 为空（聚合清单不得为空）"
}

Write-Host "== 校验 $($mf.files.Count) 个登记文件的 sha256 =="
foreach ($f in $mf.files) {
    $p = Join-Path $FromDir ($f.path -replace '/', [IO.Path]::DirectorySeparatorChar)
    if (-not (Test-Path $p)) { Fail "manifest 登记的文件不存在：$($f.path)" }
    $got = (Get-FileHash -Algorithm SHA256 -Path $p).Hash.ToLower()
    if ($got -ne $f.sha256.ToLower()) {
        Fail "sha256 不匹配：$($f.path)（manifest 期望 $($f.sha256)，实际 $got）——文件被改动或 manifest 未同步"
    }
}
Write-Host "✅ 全部登记文件 hash 一致"

# ---- 2. 评测记录与发布状态判定（硬门禁：无 bench 记录只能 draft）----

$bench = $null
if ($BenchJson -ne "") {
    if (-not (Test-Path $BenchJson)) { Fail "评测记录不存在：$BenchJson" }
    $bench = Get-Content $BenchJson -Raw | ConvertFrom-Json
    if ($bench.version -ne $Version) {
        Fail "评测记录的 version=$($bench.version) 与 -Version=$Version 不一致（记录与版本须一一对应）"
    }
    foreach ($k in @("corpus_sha256", "rule_detect", "semantic_detect", "fp", "passed")) {
        if ($null -eq $bench.$k) { Fail "评测记录缺字段：$k（须与 policyBenchRecord 同构）" }
    }
    if ([string]::IsNullOrWhiteSpace($bench.corpus_sha256)) {
        Fail "评测记录 corpus_sha256 为空（无语料指纹则不可与基线比较）"
    }
}
$status = if ($null -ne $bench) { "published" } else { "draft" }
Write-Host "== 版本状态：$status =="
if ($status -eq "draft") {
    Write-Host "   （无 -BenchJson ⇒ 只能归档为 draft；draft 不可被 activate）" -ForegroundColor Yellow
}

$versionsDir = Join-Path $PolicyDir "versions"
$targetDir = Join-Path $versionsDir $Version
if (Test-Path $targetDir) {
    Fail "版本快照已存在（历史版本不可覆盖）：$targetDir —— 如需修订请换版本号"
}

# ---- 3. 复制快照 ----

New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
Copy-Item -Path (Join-Path $FromDir "*") -Destination $targetDir -Recurse -Force
if ($null -ne $bench) {
    Copy-Item -Path $BenchJson -Destination (Join-Path $targetDir "bench.json") -Force
}
Write-Host "✅ 快照已写入：$targetDir"

# ---- 4. 维护 versions/index.json ----

$indexPath = Join-Path $versionsDir "index.json"
if (Test-Path $indexPath) {
    $index = Get-Content $indexPath -Raw | ConvertFrom-Json
    if ($index.schema_version -ne "1.0") {
        Fail "index.schema_version=$($index.schema_version) 不受支持（期望 1.0）"
    }
} else {
    $index = [pscustomobject]@{ schema_version = "1.0"; baseline = $null; versions = @() }
}

if ($InitBaseline) {
    if ($null -eq $bench) { Fail "-InitBaseline 须同时提供 -BenchJson（基线由首次评测记录自举，不预置）" }
    if ($null -ne $index.baseline) { Fail "基线已登记，不可重复自举（如需变更须显式评审后手改 index 并留痕）" }
    $index.baseline = [pscustomobject]@{
        rule_detect     = [double]$bench.rule_detect
        semantic_detect = [double]$bench.semantic_detect
        fp              = [double]$bench.fp
        corpus_sha256   = [string]$bench.corpus_sha256
    }
    Write-Host "✅ 基线已自举（rule_detect=$($bench.rule_detect) semantic_detect=$($bench.semantic_detect) fp=$($bench.fp)）"
} elseif ($null -eq $index.baseline) {
    Write-Host "⚠️  index.baseline 仍为空：该版本发布后**无法通过 bench 硬门禁**（activate 将报 baseline_not_registered）。" -ForegroundColor Yellow
    Write-Host "    如需自举基线，请以本次评测记录重跑并加 -InitBaseline；若已完成，用 -Note 记录后重跑同参数。" -ForegroundColor Yellow
}

$entry = [pscustomobject]@{
    version    = $Version
    status     = $status
    note       = $Note
    created_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}
$kept = @($index.versions | Where-Object { $_.version -ne $Version })
$index.versions = @($kept + $entry)

$index | ConvertTo-Json -Depth 8 | Set-Content -Path $indexPath -Encoding UTF8
Write-Host "✅ 索引已更新：$indexPath"

# ---- 5. 后续校验提示 ----

Write-Host ""
Write-Host "下一步（Go 侧发布门禁，逐版本复算哈希 + bench 门禁）："
Write-Host "  go test -mod=mod ./gateway/tee-infer-service/ -run TestPolicyVersionArtifactsVerify -v"
Write-Host "运行时引用（经管理端点，须过 bench 硬门禁）："
Write-Host "  POST /config/policy/activate {\"version\":\"$Version\"}"
