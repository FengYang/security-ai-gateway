#Requires -Version 5.1
<#
  build-compliance-table.ps1 —— 合规映射表生成与校验
  （Phase 2 §4.5 合规映射表；Phase 3 门禁 #3「合规报告一键生成」的数据底座）

  单一事实源：docs/compliance/controls/*.json（按标准一文件，条款级逐条）
  产出：       docs/GA-合规映射表.md（内部资产，不入 git；JSON 亦不入 git）

  用途：
    1) 校验（失败 exit 1，可作门禁）：枚举值合法、ok|partial 必须有证据锚点、
       gap|na 必须写理由、等保/金融不得自填条款号（离线无标准原文）、GDPR 必须写 Article 号；
    2) 生成 Markdown 汇总（覆盖度 + 分组统计 + 逐条明细 + 缺口清单 + 待原文复核清单）；
    3) 输出证据锚点的路径存在性提示（仅对形如路径的锚点，缺失仅告警不失败）。

  运行：powershell -ExecutionPolicy Bypass -File scripts\build-compliance-table.ps1
#>
param(
    [string]$InDir = (Join-Path $PSScriptRoot '..\docs\compliance\controls'),
    [string]$OutFile = (Join-Path $PSScriptRoot '..\docs\GA-合规映射表.md')
)

$ErrorActionPreference = 'Stop'

# 口径常量（与 JSON schema 一致；改这里必须同步 docs/compliance/controls/*.json）
# 注：云计算安全扩展要求的分工本质是「云服务商 vs 云租户」，故 applicability 增加 provider_side、
# owner 增加 云服务商（否则该章节的责任划分会被压进"客户侧"而失真）。
$StatusOrder = @('ok', 'partial', 'gap', 'na')
$StatusLabel = @{ ok = '✅ 已具备'; partial = '🔶 部分具备'; gap = '⛔ 缺口'; na = '➖ 不适用' }
$ApplicabilityLabel = @{ applicable = '适用（本方）'; client_side = '云租户/客户侧责任'; provider_side = '云服务商/基础设施方责任'; out_of_scope = '不在本产品形态范围' }
$EvidenceTypes = @('code', 'doc', 'test', 'runtime')
$EvidenceTypeLabel = @{ code = '代码'; doc = '文档'; test = '测试/门禁'; runtime = '运行时' }
$OwnerValues = @('本方', '客户侧', '云服务商', '共同')
$NoClauseRefStandards = @('dengbao-ji3', 'dengbao-ji3-cloud', 'finance-jrt')   # 离线无标准原文：不得自填条款号
$ItemFields = @('group', 'control_point', 'ref', 'ref_note', 'requirement', 'requirement_source',
    'retrieval', 'status', 'applicability', 'evidence', 'gap', 'owner', 'note')

$errors = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]
$docs = New-Object System.Collections.Generic.List[object]

# ---------- 载入与校验 ----------
$files = Get-ChildItem -Path $InDir -Filter '*.json' | Sort-Object Name
if ($files.Count -eq 0) {
    Write-Error "未找到任何合规源文件：$InDir"
}
foreach ($f in $files) {
    $raw = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
    try { $doc = $raw | ConvertFrom-Json } catch { $errors.Add("$($f.Name): JSON 解析失败: $_"); continue }
    foreach ($field in @('standard', 'standard_id', 'scope_note', 'sources', 'controls')) {
        if (-not $doc.PSObject.Properties.Name.Contains($field)) { $errors.Add("$($f.Name): 缺顶层字段 $field") }
    }
    $idx = 0
    foreach ($c in $doc.controls) {
        $idx++
        $where = "$($f.Name)#$idx"
        foreach ($field in $ItemFields) {
            if (-not $c.PSObject.Properties.Name.Contains($field)) { $errors.Add("${where}: 缺字段 $field") }
        }
        if ($StatusOrder -notcontains $c.status) { $errors.Add("${where}: status 非法 '$($c.status)'") }
        if ($ApplicabilityLabel.Keys -notcontains $c.applicability) { $errors.Add("${where}: applicability 非法 '$($c.applicability)'") }
        if ($OwnerValues -notcontains $c.owner) { $errors.Add("${where}: owner 非法 '$($c.owner)'") }

        $ev = @($c.evidence)
        if (($c.status -eq 'ok' -or $c.status -eq 'partial') -and $ev.Count -eq 0) {
            $errors.Add("${where}: status=$($c.status) 但缺少证据锚点（禁止无证据的达标声明）")
        }
        if (($c.status -eq 'gap' -or $c.status -eq 'na') -and [string]::IsNullOrWhiteSpace($c.gap)) {
            $errors.Add("${where}: status=$($c.status) 但未写理由（gap 字段必填）")
        }
        foreach ($e in $ev) {
            if ($EvidenceTypes -notcontains $e.type) { $errors.Add("${where}: evidence.type 非法 '$($e.type)'") }
            if ([string]::IsNullOrWhiteSpace($e.ref)) { $errors.Add("${where}: evidence.ref 为空") }
        }
        if ($NoClauseRefStandards -contains $doc.standard_id) {
            if (-not [string]::IsNullOrWhiteSpace($c.ref)) {
                $errors.Add("${where}: 标准 $($doc.standard_id) 离线无原文，ref 必须留空（不得臆造条款号），实际 '$($c.ref)'")
            }
            if ([string]::IsNullOrWhiteSpace($c.ref_note)) { $errors.Add("${where}: ref_note 必须说明条款号待复核") }
        }
        if ($doc.standard_id -eq 'gdpr') {
            if ($c.ref -notmatch '^Art\.\d+') { $errors.Add("${where}: GDPR 条目 ref 必须为 Art.<n>，实际 '$($c.ref)'") }
        }
        # 证据锚点路径存在性（仅对形如路径者；缺失仅告警）
        foreach ($e in $ev) {
            if ($e.type -eq 'runtime') { continue }
            $ref = [string]$e.ref
            if ($ref -match '[\\/]' -or $ref -match '\.(go|ps1|json|md|yaml|yml|sh)$') {
                $candidate = Join-Path (Join-Path $PSScriptRoot '..') $ref
                if (-not (Test-Path $candidate)) { $warnings.Add("${where}: 证据锚点路径不存在 -> $ref") }
            }
        }
    }
    $docs.Add($doc)
}

if ($errors.Count -gt 0) {
    Write-Output "== 校验失败（$($errors.Count) 项） =="
    $errors | ForEach-Object { Write-Output "  - $_" }
    exit 1
}

# ---------- 生成 Markdown ----------
$sb = New-Object System.Text.StringBuilder
function Add-Line([string]$text = '') { [void]$sb.AppendLine($text) }

function Escape-Cell([string]$s) {
    if ($null -eq $s) { return '' }
    $t = $s -replace "\r?\n", ' '
    $t = $t -replace '\|', '\|'
    return $t
}
function Clip([string]$s, [int]$n) {
    if ($null -eq $s) { return '' }
    $t = (Escape-Cell $s)
    if ($t.Length -le $n) { return $t }
    return $t.Substring(0, $n) + '…'
}

Add-Line '# GA 合规映射表（等保 2.0 三级 / 金融数据安全 / GDPR）'
Add-Line ''
Add-Line '> **文档定位**：Phase 2 §4.5「合规映射表」交付物；服务 Phase 3 门禁 #3「合规报告一键生成」。'
Add-Line '> **本质**：**适用性判定 + 差距分析**，不构成测评结论、不构成法律意见。'
Add-Line "> **生成方式**：由 ``scripts/build-compliance-table.ps1`` 从 ``docs/compliance/controls/*.json``（单一事实源）生成，**勿手工编辑本文件**。"
Add-Line "> **生成时间**：$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"
Add-Line ''
Add-Line '## 0. 口径与局限（务必先读）'
Add-Line ''
Add-Line '1. **条款号来源**：等保 2.0（GB/T 22239-2019：第三级**安全通用要求**与**云计算安全扩展要求**）与金融标准（JR/T 0223-2021、JR/T 0197-2020）**离线无可核验的标准原文**，故本表不使用正式条款号（`ref` 留空），'
Add-Line '   要求项文本按 ≥2 个相互独立公开来源交叉核验后整理，**条款号与措辞须以标准原文复核**（见「待标准原文复核清单」节）。GDPR 为公开文本，Article 编号可直接核验。'
Add-Line '2. **四态口径**：✅ 已具备（有可核验证据锚点）｜🔶 部分具备（有证据但不完整）｜⛔ 缺口（应做而未做）｜➖ 不适用（写明理由，区分"不在产品形态范围"与"由谁承载"）。'
Add-Line '3. **证据锚点**：仅接受四类可核验证据——`code`（代码路径）｜`doc`（内部文档）｜`test`（测试/门禁产物）｜`runtime`（运行时产物）。'
Add-Line '   **无证据不得声明达标**（脚本已强制校验，含证据路径存在性告警）。'
Add-Line '4. **责任划分**：本产品是 **AI 网关组件**（云原生形态），不是整机信息系统，也不含机房、终端、办公网与人员组织；也不提供 IaaS/PaaS 能力。'
Add-Line '   故物理环境/组织机构类条款多为 ➖（客户/委托方责任）；**云计算安全扩展要求**的分工按「云服务商（`provider_side`）／云租户-客户侧（`client_side`）／本产品（`applicable`）」逐条判定并写明承载方。'
Add-Line ''
Add-Line '## 1. 覆盖度汇总'
Add-Line ''
Add-Line '| 标准 | 条数 | ✅ 已具备 | 🔶 部分具备 | ⛔ 缺口 | ➖ 不适用 |'
Add-Line '| --- | --- | --- | --- | --- | --- |'
$grandTotal = 0
$grandStatus = @{}
foreach ($s in $StatusOrder) { $grandStatus[$s] = 0 }
foreach ($doc in $docs) {
    $counts = @{}
    foreach ($s in $StatusOrder) { $counts[$s] = @($doc.controls | Where-Object status -eq $s).Count }
    $n = @($doc.controls).Count
    $grandTotal += $n
    foreach ($s in $StatusOrder) { $grandStatus[$s] += $counts[$s] }
    Add-Line ("| {0} | {1} | {2} | {3} | {4} | {5} |" -f (Escape-Cell $doc.standard), $n,
        $counts['ok'], $counts['partial'], $counts['gap'], $counts['na'])
}
Add-Line ("| **合计** | **{0}** | **{1}** | **{2}** | **{3}** | **{4}** |" -f $grandTotal,
    $grandStatus['ok'], $grandStatus['partial'], $grandStatus['gap'], $grandStatus['na'])
Add-Line ''

$secNo = 2
foreach ($doc in $docs) {
    Add-Line ("## {0}. {1}" -f $secNo, (Escape-Cell $doc.standard))
    Add-Line ''
    Add-Line ("- 口径：{0}" -f (Escape-Cell $doc.scope_note))
    Add-Line ''
    Add-Line '### 分组统计'
    Add-Line ''
    Add-Line '| 分组 | 条数 | ✅ | 🔶 | ⛔ | ➖ |'
    Add-Line '| --- | --- | --- | --- | --- | --- |'
    foreach ($g in ($doc.controls | Group-Object group | Sort-Object Name)) {
        $gc = @{}
        foreach ($s in $StatusOrder) { $gc[$s] = @($g.Group | Where-Object status -eq $s).Count }
        Add-Line ("| {0} | {1} | {2} | {3} | {4} | {5} |" -f (Escape-Cell $g.Name), $g.Count,
            $gc['ok'], $gc['partial'], $gc['gap'], $gc['na'])
    }
    Add-Line ''
    Add-Line '### 逐条明细'
    Add-Line ''
    Add-Line '> 要求项要点与缺口为**节选**（完整文本与全部证据见 `docs/compliance/controls/*.json`，单一事实源）。'
    Add-Line ''
    Add-Line '| 分组 | 控制点 / 条款 | 要求项要点 | 状态 | 适用性 · 责任 | 证据锚点 | 缺口 / 不适用理由 |'
    Add-Line '| --- | --- | --- | --- | --- | --- | --- |'
    foreach ($c in $doc.controls) {
        $evText = (@($c.evidence) | ForEach-Object { "[$($EvidenceTypeLabel[$_.type])] $($_.ref)" }) -join '<br>'
        $refCell = if ([string]::IsNullOrWhiteSpace($c.ref)) { (Escape-Cell $c.control_point) } else { "$($c.ref) $([char]0x00B7) $(Escape-Cell $c.control_point)" }
        Add-Line ("| {0} | {1} | {2} | {3} | {4} · {5} | {6} | {7} |" -f
            (Clip $c.group 40), $refCell, (Clip $c.requirement 200),
            $StatusLabel[$c.status], $ApplicabilityLabel[$c.applicability], (Escape-Cell $c.owner),
            (Clip $evText 220), (Clip $c.gap 240))
    }
    Add-Line ''
    $secNo++
}

# ---------- 行动清单 ----------
Add-Line ("## {0}. 缺口清单（⛔，按责任方）" -f $secNo)
Add-Line ''
Add-Line '> 这些是**应做而未做**的项：要么在 roadmap 中已排期（如 WAF/OIDC/KMS），要么为新增缺口（需评估是否纳入）。'
Add-Line ''
Add-Line '| 标准 | 分组 · 控制点 | 适用性 · 责任 | 缺口 |'
Add-Line '| --- | --- | --- | --- |'
foreach ($doc in $docs) {
    foreach ($c in ($doc.controls | Where-Object status -eq 'gap')) {
        Add-Line ("| {0} | {1} · {2} | {3} · {4} | {5} |" -f
            (Clip $doc.standard 30), (Clip $c.group 30), (Escape-Cell $c.control_point),
            $ApplicabilityLabel[$c.applicability], (Escape-Cell $c.owner), (Clip $c.gap 300))
    }
}
Add-Line ''
$secNo++

Add-Line ("## {0}. 待标准原文复核清单" -f $secNo)
Add-Line ''
Add-Line '> 等保与金融标准的**正式条款号与措辞**须以标准原文复核后方可作为对外交付；本表的条款位置仅以控制点/章节名标识。'
Add-Line ''
Add-Line '| 标准 | 待复核条目数 | 说明（各条 ref_note 一致，此处给出唯一取值） |'
Add-Line '| --- | --- | --- |'
foreach ($doc in $docs) {
    $pending = @($doc.controls | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ref_note) })
    if ($pending.Count -eq 0) { continue }
    $notes = ($pending | Select-Object -ExpandProperty ref_note -Unique) -join ' ／ '
    Add-Line ("| {0} | {1} | {2} |" -f (Escape-Cell $doc.standard), $pending.Count, (Clip $notes 300))
}
Add-Line ''
$secNo++

$unretrieved = @()
foreach ($doc in $docs) {
    foreach ($c in ($doc.controls | Where-Object { $_.retrieval -eq $false })) {
        $unretrieved += [pscustomobject]@{ Standard = $doc.standard; Group = $c.group; Point = $c.control_point; Gap = $c.gap }
    }
}
Add-Line ("## {0}. 要求项文本未能交叉核验清单（retrieval=false）" -f $secNo)
Add-Line ''
if ($unretrieved.Count -eq 0) {
    Add-Line '无（全部条目均经 ≥2 个独立来源交叉核验）。'
} else {
    Add-Line '> 以下条目**保留条款骨架但未取得可核验文本**，严禁据此对外声称符合性；需以标准原文补齐。'
    Add-Line ''
    Add-Line '| 标准 | 分组 · 控制点 | 当前处理 |'
    Add-Line '| --- | --- | --- |'
    foreach ($u in $unretrieved) {
        Add-Line ("| {0} | {1} · {2} | {3} |" -f (Clip $u.Standard 30), (Clip $u.Group 30), (Escape-Cell $u.Point), (Clip $u.Gap 200))
    }
}
Add-Line ''
$secNo++

Add-Line ("## {0}. 来源清单（交叉核验用）" -f $secNo)
Add-Line ''
foreach ($doc in $docs) {
    Add-Line ("### {0}" -f (Escape-Cell $doc.standard))
    Add-Line ''
    foreach ($s in $doc.sources) {
        $title = if ($s.PSObject.Properties.Name.Contains('title')) { $s.title } else { '(无标题)' }
        $url = if ($s.PSObject.Properties.Name.Contains('url')) { $s.url } else { '' }
        $note = if ($s.PSObject.Properties.Name.Contains('note')) { $s.note } else { '' }
        Add-Line ("- {0} — {1}{2}" -f (Escape-Cell $title), (Escape-Cell $url), $(if ($note) { "（$((Escape-Cell $note))）" } else { '' }))
    }
    Add-Line ''
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$outPath = if ([System.IO.Path]::IsPathRooted($OutFile)) { $OutFile } else { Join-Path (Get-Location) $OutFile }
[System.IO.File]::WriteAllText($outPath, $sb.ToString(), $utf8NoBom)

# ---------- 控制台摘要 ----------
Write-Output "== 合规映射表已生成 =="
Write-Output "  源目录：$InDir"
Write-Output "  产出：  $OutFile"
foreach ($doc in $docs) {
    $counts = @{}
    foreach ($s in $StatusOrder) { $counts[$s] = @($doc.controls | Where-Object status -eq $s).Count }
    Write-Output ("  - {0}: {1} 条（ok={2} partial={3} gap={4} na={5}）" -f $doc.standard_id, @($doc.controls).Count,
        $counts['ok'], $counts['partial'], $counts['gap'], $counts['na'])
}
Write-Output ("  合计：{0} 条；⛔ 缺口 {1} 条；retrieval=false {2} 条" -f $grandTotal, $grandStatus['gap'], $unretrieved.Count)
if ($warnings.Count -gt 0) {
    Write-Output ("  ⚠ 证据锚点路径告警 {0} 条（不阻断）：" -f $warnings.Count)
    $warnings | Select-Object -First 20 | ForEach-Object { Write-Output "     - $_" }
}
Write-Output "  校验：通过（枚举合法、ok|partial 均有证据、gap|na 均有理由、无臆造条款号）"
exit 0
