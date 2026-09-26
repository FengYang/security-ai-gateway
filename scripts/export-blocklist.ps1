# export-blocklist.ps1 — 导出备案用「拦截关键词列表」与类目覆盖统计（B2-4）
#
# 定位：从 tee-infer 策略目录（policy/）导出拦截关键词列表与类目覆盖统计，
#       供《备案材料支持包》使用；**如实标注占位态**（占位词库不得直接对外申报）。
# 完整性：默认按 manifest.json 逐文件校验 SHA-256（证明词库未被篡改/替换）。
# 用法：
#   powershell -ExecutionPolicy Bypass -File scripts\export-blocklist.ps1
#   ... -PolicyDir <dir> -OutDir <dir> [-SkipVerify]
# 退出码：0 = 导出成功且校验通过｜1 = 完整性校验失败（sha256 不匹配或文件缺失）｜2 = 输入缺失/脚本错误
#
# 注：脚本自身字面量为 UTF-8（含中文，需 UTF-8 BOM 保存）；输入一律显式 -Encoding UTF8 读取，
#     输出 CSV 为 UTF-8 with BOM（便于 Excel 打开），JSON 为 UTF-8。

param(
    [string]$PolicyDir = 'gateway/tee-infer-service/policy',
    [string]$OutDir = 'docs/compliance/export/blocklist',
    [switch]$SkipVerify
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
if (-not [System.IO.Path]::IsPathRooted($PolicyDir)) { $PolicyDir = Join-Path $repoRoot $PolicyDir }
if (-not [System.IO.Path]::IsPathRooted($OutDir)) { $OutDir = Join-Path $repoRoot $OutDir }

# 官方量级（GB/T 45654-2025 §8.1 / 原 TC260-003 §8.1）：总规模不宜少于 10000；
# 覆盖附录 A.1+A.2 共 17 种；A.1 每类不宜少于 200、A.2 每类不宜少于 100。
$official = @{
    total_min       = 10000
    per_family_min  = @{ 'A1' = 200; 'A2' = 100 }
    covered_families = @('A1', 'A2')
}

$manifestPath = Join-Path $PolicyDir 'manifest.json'
$categoriesPath = Join-Path $PolicyDir 'categories.json'
if (-not (Test-Path -LiteralPath $manifestPath)) { Write-Host "FAIL: manifest.json not found: $manifestPath"; exit 2 }
if (-not (Test-Path -LiteralPath $categoriesPath)) { Write-Host "FAIL: categories.json not found: $categoriesPath"; exit 2 }

Write-Host "== B2-4 blocklist export =="
Write-Host "policy dir : $PolicyDir"
Write-Host "out dir    : $OutDir"

$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
Write-Host ("policy_version={0}  schema_version={1}" -f $manifest.policy_version, $manifest.schema_version)

# ---- 1) 完整性校验（manifest 逐文件 sha256）----
$mismatch = @()
$missing = @()
$verified = 0
if (-not $SkipVerify) {
    foreach ($f in $manifest.files) {
        $p = Join-Path $PolicyDir $f.path
        if (-not (Test-Path -LiteralPath $p)) { $missing += $f.path; continue }
        $actual = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower()
        if ($actual -ne $f.sha256.ToLower()) { $mismatch += ("{0} (manifest={1} actual={2})" -f $f.path, $f.sha256, $actual) }
        else { $verified++ }
    }
    Write-Host ("integrity  : verified={0} mismatch={1} missing={2}" -f $verified, $mismatch.Count, $missing.Count)
}

# ---- 2) 类目表（31 类：id/name/family/level/action）----
$categories = Get-Content -LiteralPath $categoriesPath -Raw -Encoding UTF8 | ConvertFrom-Json
$catById = @{}
foreach ($c in $categories) { $catById[$c.id] = $c }

# ---- 3) 逐类词库（keywords/*.json）----
$rows = New-Object System.Collections.Generic.List[object]
$perCat = @{}
$placeholderState = $false
$entriesTotal = 0
$placeholderTotal = 0

$kwDir = Join-Path $PolicyDir 'keywords'
$kwFiles = @()
if (Test-Path -LiteralPath $kwDir) { $kwFiles = Get-ChildItem -LiteralPath $kwDir -Filter '*.json' | Sort-Object Name }

foreach ($file in $kwFiles) {
    $doc = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    $cid = $doc.category
    $n = 0
    $ph = 0
    foreach ($r in $doc.rules) {
        $isPlaceholder = $false
        if ($r.keyword -match '示例') { $isPlaceholder = $true }
        if ($r.comment -and $r.comment -match '占位') { $isPlaceholder = $true }
        if ($isPlaceholder) { $ph++ }
        $cat = $catById[$cid]
        $catName = ''
        $family = ''
        if ($cat) { $catName = $cat.name; $family = $cat.family }
        $rows.Add([pscustomobject]@{
            category_id   = $cid
            category_name = $catName
            family        = $family
            level         = $doc.level
            rule_id       = $r.id
            keyword       = $r.keyword
            type          = $r.type
            weight        = $r.weight
            added_at      = $r.added_at
            submitter     = $r.submitter
            reviewer      = $r.reviewer
            placeholder   = $isPlaceholder
        })
        $n++
    }
    $perCat[$cid] = [pscustomobject]@{ entries = $n; placeholders = $ph; version = $doc.version; level = $doc.level }
    $entriesTotal += $n
    $placeholderTotal += $ph
    if ($ph -gt 0) { $placeholderState = $true }
}

# ---- 4) 覆盖与量级对照（31 类 / 17 类 / 官方门槛）----
$catIds = @($categories | ForEach-Object { $_.id })
$covered = @($perCat.Keys | Sort-Object)
$notCovered = @($catIds | Where-Object { -not $perCat.ContainsKey($_) })
# 区分"设计内不建 keyword 词库"与"真实缺口"（依据 categories.json 的 note）
$designExempt = @()
$realGap = @()
foreach ($id in $notCovered) {
    $note = ''
    if ($catById[$id] -and $catById[$id].note) { $note = $catById[$id].note }
    if ($note -match '兜底|不单独建词库|只标记|maskPII') { $designExempt += $id } else { $realGap += $id }
}
$famStats = @{}
foreach ($fam in @('A1', 'A2', 'A3', 'A4', 'A5')) {
    $famIds = @($categories | Where-Object { $_.family -eq $fam } | ForEach-Object { $_.id })
    $famCovered = @($famIds | Where-Object { $perCat.ContainsKey($_) })
    $famEntries = 0
    foreach ($id in $famCovered) { $famEntries += $perCat[$id].entries }
    $min = 0
    if ($official.per_family_min.ContainsKey($fam)) { $min = $official.per_family_min[$fam] }
    $below = 0
    if ($min -gt 0) { $below = @($famCovered | Where-Object { $perCat[$_].entries -lt $min }).Count }
    $famStats[$fam] = [pscustomobject]@{
        categories        = $famIds.Count
        with_lexicon      = $famCovered.Count
        entries           = $famEntries
        official_min_each = $min
        categories_below_official_min = $below
    }
}

# ---- 5) 输出 ----
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$csvAll = Join-Path $OutDir 'blocklist.csv'
$csvKeywords = Join-Path $OutDir 'blocklist-keywords-only.csv'
$jsonSummary = Join-Path $OutDir 'export-summary.json'
$mdSummary = Join-Path $OutDir 'export-summary.md'

$rows | Export-Csv -LiteralPath $csvAll -NoTypeInformation -Encoding UTF8
$rows | Select-Object category_id, category_name, keyword | Export-Csv -LiteralPath $csvKeywords -NoTypeInformation -Encoding UTF8

$summary = [pscustomobject]@{
    generator            = 'scripts/export-blocklist.ps1'
    generated_at         = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
    policy_version       = $manifest.policy_version
    schema_version       = $manifest.schema_version
    manifest_sha256      = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLower()
    integrity            = [pscustomobject]@{ skipped = [bool]$SkipVerify; verified = $verified; mismatch = $mismatch; missing = $missing }
    categories_total     = $catIds.Count
    categories_with_lexicon = $covered.Count
    categories_not_covered  = $notCovered
    categories_not_covered_design_exempt = $designExempt
    categories_not_covered_gap          = $realGap
    entries_total        = $entriesTotal
    placeholder_entries  = $placeholderTotal
    placeholder_state    = $placeholderState
    official_min_total   = $official.total_min
    below_official_total = ($entriesTotal -lt $official.total_min)
    family_stats         = $famStats
    files                = [pscustomobject]@{ all_rows_csv = 'blocklist.csv'; keywords_only_csv = 'blocklist-keywords-only.csv' }
}
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonSummary -Encoding UTF8

# 人读摘要（中文；内容由数据与固定标签构成）
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('# 拦截关键词列表 · 导出摘要（B2-4）')
$lines.Add('')
$lines.Add(('- 生成时间：{0}' -f $summary.generated_at))
$lines.Add(('- 策略版本：`{0}`（schema {1}）' -f $manifest.policy_version, $manifest.schema_version))
$lines.Add(('- manifest SHA-256：`{0}`' -f $summary.manifest_sha256))
if ($SkipVerify) { $lines.Add('- 完整性校验：**已跳过（-SkipVerify）**') }
else { $lines.Add(('- 完整性校验：通过 {0} 个文件；不匹配 {1}；缺失 {2}' -f $verified, $mismatch.Count, $missing.Count)) }
$lines.Add('')
$lines.Add(('## 覆盖情况（31 类中已建词库 {0} 类）' -f $covered.Count))
$lines.Add('')
$lines.Add('| 族 | 类目数 | 已建词库 | 条目数 | 官方每类下限 | 低于下限的类目数 |')
$lines.Add('| --- | --- | --- | --- | --- | --- |')
foreach ($fam in @('A1', 'A2', 'A3', 'A4', 'A5')) {
    $s = $famStats[$fam]
    $min = '-'
    if ($s.official_min_each -gt 0) { $min = $s.official_min_each }
    $below = '-'
    if ($s.official_min_each -gt 0) { $below = $s.categories_below_official_min }
    $lines.Add(('| {0} | {1} | {2} | {3} | {4} | {5} |' -f $fam, $s.categories, $s.with_lexicon, $s.entries, $min, $below))
}
$lines.Add('')
$lines.Add(('## 量级对照（官方总规模下限 {0}）' -f $official.total_min))
$lines.Add('')
$lines.Add(('- 当前条目总数：**{0}**（低于官方下限：**{1}**）' -f $entriesTotal, $summary.below_official_total))
$notCoveredText = '无'
if ($notCovered.Count -gt 0) { $notCoveredText = $notCovered -join '、' }
$lines.Add(('- 未建 keyword 词库类目：{0}' -f $notCoveredText))
$deText = '无'
if ($designExempt.Count -gt 0) { $deText = $designExempt -join '、' }
$gapText = '无'
if ($realGap.Count -gt 0) { $gapText = $realGap -join '、' }
$lines.Add(('- 　└ 设计内豁免（不建 keyword 词库，依据 `categories.json` 的 `note`）：{0}' -f $deText))
$lines.Add(('- 　└ 真实缺口（既无词库也非设计豁免）：{0}' -f $gapText))
$lines.Add('- 口径区分：**类目映射覆盖**（31 类全量映射，含官方 A.1+A.2 共 17 种）与 **keyword 词库覆盖**（28/31）是两个口径；官方"至少覆盖 A.1+A.2 共 17 种"属前者，后者按类目设计差异存在豁免。')
$lines.Add('')
$lines.Add('## 占位态（重要）')
$lines.Add('')
if ($placeholderState) {
    $lines.Add(('- ⚠️ **当前词库含占位条目 {0} 条 / 共 {1} 条**：占位条目为结构自证，**不得据此对外申报**；' -f $placeholderTotal, $entriesTotal))
    $lines.Add('  须由安全团队按 schema 填充真实词面（变更走 D8 双审）后重新导出。')
} else {
    $lines.Add('- ✅ 未检出占位条目（`keyword` 含「示例」或 `comment` 含「占位」）。')
}
$lines.Add('')
$lines.Add('## 产物')
$lines.Add('')
$lines.Add('- `blocklist.csv`：全字段明细（含 submitter/reviewer/added_at/placeholder）')
$lines.Add('- `blocklist-keywords-only.csv`：报备形态（类目 + 关键词）')
$lines.Add('- `export-summary.json`：机器可读摘要（覆盖/量级/完整性/占位态）')
$lines.Add('- `export-summary.md`：本文件')
$lines | Set-Content -LiteralPath $mdSummary -Encoding UTF8

Write-Host ("exported   : {0} rows, {1} categories covered, {2} not covered" -f $rows.Count, $covered.Count, $notCovered.Count)
if ($placeholderState) { Write-Host ("WARN: placeholder entries present: {0}/{1} -- must NOT be used for filing as-is" -f $placeholderTotal, $entriesTotal) }
if (-not $SkipVerify -and ($mismatch.Count -gt 0 -or $missing.Count -gt 0)) {
    Write-Host 'FAIL: integrity check failed (see export-summary.json)'
    exit 1
}
Write-Host "OK: $OutDir"
exit 0
