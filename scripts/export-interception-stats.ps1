# export-interception-stats.ps1 — 采集拦截统计（B2-1）
#
# 定位：从运行中的 tee-infer `/metrics` 采集**审核/拦截相关指标**，按"登记要求（required/conditional）"
#       逐项标注是否已出现，输出机器可读 JSON 与人读 MD，供《备案材料支持包》的"拦截统计"章节使用。
# 单一事实源：指标清单直接读 `scripts/metrics-required.txt`（与门禁同一清单，避免第二份口径）。
# 用法：
#   powershell -ExecutionPolicy Bypass -File scripts\export-interception-stats.ps1 -TeeToken <admin-token>
#   ... -Tee http://127.0.0.1:19090 -OutDir <dir> -Label "生产环境 2026-09"
# 退出码：0 = 采集成功｜1 = 来源不可达｜2 = 输入缺失/脚本错误
#
# 注：脚本自身字面量为 UTF-8（含中文，需 UTF-8 BOM 保存）；输出 JSON/MD 为 UTF-8。

param(
    [string]$Tee = 'http://127.0.0.1:19090',
    [string]$TeeToken = '',
    [string]$OutDir = 'docs/compliance/export/interception-stats',
    [string]$Label = '',
    [string]$MetricsFile = ''
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
if (-not [System.IO.Path]::IsPathRooted($OutDir)) { $OutDir = Join-Path $repoRoot $OutDir }
$registryPath = Join-Path $scriptDir 'metrics-required.txt'
if (-not (Test-Path -LiteralPath $registryPath)) { Write-Host "FAIL: metrics-required.txt not found"; exit 2 }

Write-Host "== B2-1 interception stats =="
Write-Host "tee    : $Tee"
Write-Host "out dir: $OutDir"

# ---- 1) 读登记清单（source=tee）----
$registry = @()
foreach ($line in (Get-Content -LiteralPath $registryPath -Encoding UTF8)) {
    $t = $line.Trim()
    if ($t -eq '' -or $t.StartsWith('#')) { continue }
    $parts = $t -split '\s+'
    if ($parts.Count -lt 3) { continue }
    if ($parts[0] -ne 'tee') { continue }
    $registry += [pscustomobject]@{ metric = $parts[1]; requirement = $parts[2] }
}
Write-Host ("registry: {0} tee metrics" -f $registry.Count)

# ---- 2) 抓取 /metrics ----
$collectedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
$raw = $null
$reachable = $false
$httpStatus = 0
if ($MetricsFile -ne '') {
    # 离线复核模式：解析已保存的 /metrics 快照（便于材料复核与回归）；来源标注为该文件
    if (-not (Test-Path -LiteralPath $MetricsFile)) { Write-Host "FAIL: -MetricsFile not found: $MetricsFile"; exit 2 }
    $raw = Get-Content -LiteralPath $MetricsFile -Raw -Encoding UTF8
    $Tee = "(offline) $MetricsFile"
    $reachable = $true
    $httpStatus = -1
    Write-Host "offline mode: $MetricsFile"
} else {
    try {
        $headers = @{}
        if ($TeeToken -ne '') { $headers['X-Admin-Token'] = $TeeToken }
        $resp = Invoke-WebRequest -UseBasicParsing -Uri ($Tee.TrimEnd('/') + '/metrics') -Headers $headers -TimeoutSec 10
        $raw = $resp.Content
        $httpStatus = $resp.StatusCode
        $reachable = $true
    } catch {
        if ($_.Exception.Response) { $httpStatus = [int]$_.Exception.Response.StatusCode }
        Write-Host ("WARN: /metrics unreachable (http={0}): {1}" -f $httpStatus, $_.Exception.Message)
    }
}

$helpMap = @{}
$samples = @{}
$rawCount = 0
if ($reachable) {
    foreach ($line in ($raw -split "`n")) {
        $l = $line.TrimEnd("`r")
        if ($l -eq '') { continue }
        if ($l.StartsWith('# HELP ')) {
            $rest = $l.Substring(7)
            $sp = $rest.IndexOf(' ')
            if ($sp -gt 0) { $helpMap[$rest.Substring(0, $sp)] = $rest.Substring($sp + 1) }
            continue
        }
        if ($l.StartsWith('#')) { continue }
        # 形如: name{k="v",k2="v2"} 12  或  name 12
        $m = [regex]::Match($l, '^(?<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?<labels>\{[^}]*\})?\s+(?<val>[-+0-9.eE]+)$')
        if (-not $m.Success) { continue }
        $name = $m.Groups['name'].Value
        $lbl = ''
        if ($m.Groups['labels'].Success) { $lbl = $m.Groups['labels'].Value }
        if (-not $samples.ContainsKey($name)) { $samples[$name] = New-Object System.Collections.Generic.List[object] }
        $samples[$name].Add([pscustomobject]@{ labels = $lbl; value = $m.Groups['val'].Value })
        $rawCount++
    }
}
Write-Host ("metrics: reachable={0} http={1} samples={2} distinct={3}" -f $reachable, $httpStatus, $rawCount, $samples.Keys.Count)

# ---- 3) 逐项判定 ----
$rows = New-Object System.Collections.Generic.List[object]
$missingRequired = @()
$presentCount = 0
foreach ($r in $registry) {
    $present = $samples.ContainsKey($r.metric)
    $sampleList = @()
    if ($present) {
        foreach ($s in $samples[$r.metric]) { $sampleList += $s }
        $presentCount++
    }
    $help = ''
    if ($helpMap.ContainsKey($r.metric)) { $help = $helpMap[$r.metric] }
    if ($r.requirement -eq 'required' -and -not $present -and $reachable) { $missingRequired += $r.metric }
    $rows.Add([pscustomobject]@{
        metric      = $r.metric
        requirement = $r.requirement
        present     = $present
        help        = $help
        samples     = $sampleList
    })
}

# ---- 4) 输出 ----
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$jsonOut = Join-Path $OutDir 'interception-stats.json'
$mdOut = Join-Path $OutDir 'interception-stats.md'

$doc = [pscustomobject]@{
    generator     = 'scripts/export-interception-stats.ps1'
    collected_at  = $collectedAt
    source        = $Tee
    source_label  = $Label
    reachable     = $reachable
    http_status   = $httpStatus
    registry_file = 'scripts/metrics-required.txt'
    registry_count = $registry.Count
    present_count = $presentCount
    missing_required = $missingRequired
    metrics       = $rows
}
$doc | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonOut -Encoding UTF8

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('# 拦截统计 · 采集快照（B2-1）')
$lines.Add('')
$lines.Add(('- 采集时间：{0}' -f $collectedAt))
$lines.Add(('- 来源：`{0}`（HTTP {1}）' -f $Tee, $httpStatus))
if ($Label -ne '') { $lines.Add(('- 环境标注：{0}' -f $Label)) }
$lines.Add(('- 指标清单来源：`scripts/metrics-required.txt`（与门禁同一清单；本脚本不另立口径）'))
$lines.Add('')
if (-not $reachable) {
    $lines.Add('> ⚠️ **来源不可达**：本快照**不含任何数据**，不得用于材料；请确认服务与令牌后重采。')
} else {
    $lines.Add(('已出现指标：**{0} / {1}**；required 缺失：**{2}**' -f $presentCount, $registry.Count, $missingRequired.Count))
}
$lines.Add('')
$lines.Add('## 逐项明细')
$lines.Add('')
$lines.Add('| 指标 | 登记要求 | 是否已出现 | 样本数 | 说明 |')
$lines.Add('| --- | --- | --- | --- | --- |')
foreach ($r in $rows) {
    $ph = '否'
    if ($r.present) { $ph = '是' }
    $h = $r.help
    if ($h -eq '') { $h = '-' }
    $lines.Add(('| `{0}` | {1} | {2} | {3} | {4} |' -f $r.metric, $r.requirement, $ph, $r.samples.Count, $h))
}
$lines.Add('')
$lines.Add('## 口径说明（重要）')
$lines.Add('')
$lines.Add('- **required 缺失**＝门禁未达成（材料中不得声明该项统计可用）。')
$lines.Add('- **conditional 未出现**＝该计数器/直方图**懒注册**（其触发事件或开关未发生），属设计内行为，不等于缺陷。')
$lines.Add('- 本快照是**时间点截面**；材料中应注明采集时间窗口与来源环境，并与被审版本对应。')
$lines.Add('- 类目级拦截明细见 `otpmask_denies_total{reason}`／`otpmask_output_guard_*{category}`；被拦 token 计量见 `filtered_tokens` 对账口径。')
$lines | Set-Content -LiteralPath $mdOut -Encoding UTF8

Write-Host ("exported: {0} (present {1}/{2}, missing_required {3})" -f $OutDir, $presentCount, $registry.Count, $missingRequired.Count)
if (-not $reachable) { Write-Host 'FAIL: source unreachable -- snapshot is empty'; exit 1 }
exit 0
