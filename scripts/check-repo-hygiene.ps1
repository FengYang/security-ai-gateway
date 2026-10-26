# scripts/check-repo-hygiene.ps1 —— P2-4 仓库卫生自检（Windows 版）
#
# 与 scripts/check-repo-hygiene.sh **逻辑等价**，供 Windows 本机开发环境使用
# （Git Bash 版见同目录 .sh；CI 推荐用 .sh）。
#
# 【只读检查】本脚本**不修改任何文件**。
#
# 【退出码语义】
#   0 = 全部**适用**检查通过（SKIP / N-A 项会在报告中显式列出）
#   1 = 存在 FAIL 项（逐项列出失败文件与判定依据）
#   2 = **环境不满足，无法判定**（缺 git / 缺 go / 显式 -SkipBuild）→ 不冒充通过
#
# 【用法】
#   powershell -ExecutionPolicy Bypass -File scripts/check-repo-hygiene.ps1
#   powershell -File scripts/check-repo-hygiene.ps1 -SkipBuild
#   powershell -File scripts/check-repo-hygiene.ps1 -DocsRepo C:\path\to\docs
#   powershell -File scripts/check-repo-hygiene.ps1 -ExtraGofmtDir gateway/gateway-core/
#
# 【实现要点（Windows 专项）】
#   * 本文件以 **UTF-8 + BOM** 保存：Windows PowerShell 5.1 无 BOM 时按 ANSI 解析，
#     中文注释会乱码并直接导致语法错误；
#   * 对**原生可执行程序**（gofmt/go/git）一律使用**仓库相对路径**并先 `Set-Location` 到仓库根：
#     仓库路径含中文（`方案`）时，绝对路径经 5.1 的 ANSI 转换会打挂原生程序 → **静默假通过**；
#   * 每个原生程序调用都校验 `$LASTEXITCODE`：非 0 一律按「无法判定（SKIP）」处理，**绝不当作通过**。

[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [string]$DocsRepo = '',
    [string[]]$ExtraGofmtDir = @(),
    [string[]]$GofmtDir = @('gateway/gateway-core/', 'gateway/gateway-admin-service/')
)

$ErrorActionPreference = 'Continue'
# Windows 专项：PowerShell 5.1 默认用 ANSI 解码文件与原生程序输出，
# 仓库内中文注释会被解码成乱码 → 与 gofmt 的 UTF-8 输出比对必然不等 → **假漂移**。
# 统一把控制台/管道编码切到 UTF-8，并在读文件时显式 -Encoding UTF8。
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }
$script:FailCount = 0
$script:SkipCount = 0
$script:NaCount = 0
$script:Blockers = @()

function Say([string]$Text = '') { Write-Output $Text }
function Rule { Write-Output ('---------------------------------------------------------------') }

function Section([string]$Id, [string]$Title) {
    Rule; Write-Output "[$Id] $Title"; Rule
}
function VerdictPass([string]$Text) { Write-Output "  判定: PASS —— $Text" }
function VerdictFail([string]$Text) { Write-Output "  判定: FAIL —— $Text"; $script:FailCount++ }
function VerdictSkip([string]$Text) { Write-Output "  判定: SKIP（无法判定）—— $Text"; $script:SkipCount++ }
function VerdictNa([string]$Text) { Write-Output "  判定: N/A（本次不适用）—— $Text"; $script:NaCount++ }

function ShowCmd([string]$Cmd) { Write-Output "  命令: $Cmd" }
function ShowOut([string]$Title, [string]$Out) {
    if ([string]::IsNullOrWhiteSpace($Out)) { Write-Output '  输出: （无）'; return }
    Write-Output "  输出（前 20 行）:"
    $lines = $Out -split "`r?`n"
    $lines | Select-Object -First 20 | ForEach-Object { Write-Output "    | $_" }
    if ($lines.Count -gt 20) { Write-Output "    | …（共 $($lines.Count) 行，已截断）" }
}

# ---------------------------------------------------------------- 定位仓库根
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Say '环境不满足：本机没有 git（无法判定仓库卫生）→ 退出码 2'
    exit 2
}
$root = (& git rev-parse --show-toplevel 2>$null)
if ([string]::IsNullOrWhiteSpace($root)) {
    Say '环境不满足：不在 git 仓库内（无法判定仓库卫生）→ 退出码 2'
    exit 2
}
Set-Location $root
$rootLabel = (& git rev-parse --show-toplevel 2>$null)

Say '==============================================================='
Say 'check-repo-hygiene.ps1 —— P2-4 仓库卫生自检'
Say "仓库根: $rootLabel"
Say "HEAD:   $(& git rev-parse --short HEAD 2>$null)"
Say "模式:   $(if ($SkipBuild) { '跳过 C1 构建三连（-SkipBuild）' } else { '全量检查' })"
Say '==============================================================='

# ---------------------------------------------------------------- 定位 docs 库（相对路径优先）
# 说明：docs 是**独立 git 库**；默认用**相对路径** 'docs'，避免中文绝对路径打挂原生程序。
$docsRel = ''
if ($DocsRepo -ne '') {
    if (Test-Path -LiteralPath $DocsRepo) { $docsRel = (Resolve-Path -LiteralPath $DocsRepo).Path }
} elseif (Test-Path -LiteralPath 'docs/.git') {
    $docsRel = 'docs'
}

# ================================================================ C1 构建三连
Section 'C1' '构建三连（CI 同款：go build / go vet / go test 编译校验）'
if ($SkipBuild) {
    VerdictSkip '显式 -SkipBuild：构建三连未执行 → 本次**不能**作为全量门禁依据（退出码 2）'
    $script:Blockers += ' 构建三连(-SkipBuild)'
} elseif (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    VerdictSkip '本机没有 go（无法执行构建三连）→ 退出码 2'
    $script:Blockers += ' 缺go'
} else {
    Say "  go 版本: $(& go env GOVERSION 2>$null)"
    # 工具链版本门槛：低于 go.mod 要求 → 无法判定（环境问题，不是仓库卫生问题）
    $gomodVer = ''
    if (Test-Path -LiteralPath 'go.mod') {
        $line = (Get-Content -LiteralPath 'go.mod' -Encoding UTF8 | Where-Object { $_ -match '^go\s+\d' } | Select-Object -First 1)
        if ($line) { $gomodVer = ($line -split '\s+')[1] }
    }
    $goLocal = ((& go env GOVERSION 2>$null) -replace '^go', '')
    $tooOld = $false
    if ($gomodVer -and $goLocal) {
        $lo = $goLocal -split '\.'; $mo = $gomodVer -split '\.'
        if ([int]$lo[0] -lt [int]$mo[0]) { $tooOld = $true }
        elseif ([int]$lo[0] -eq [int]$mo[0] -and [int]$lo[1] -lt [int]$mo[1]) { $tooOld = $true }
    }
    if ($tooOld) {
        VerdictSkip "本机 Go 版本 $goLocal 低于 go.mod 要求 $gomodVer → 构建三连无法判定（环境不满足）→ 退出码 2"
        $script:Blockers += " Go版本过低($goLocal<$gomodVer)"
    } else {
        $steps = @(
            @{ Name = 'build'; Cmd = 'go build ./...' },
            @{ Name = 'vet'; Cmd = 'go vet ./...' },
            @{ Name = 'test'; Cmd = 'go test -run NoSuchTestPattern__repo_hygiene_probe__ ./...' }
        )
        $c1Fail = 0
        foreach ($s in $steps) {
            ShowCmd $s.Cmd
            $out = & ([scriptblock]::Create($s.Cmd)) 2>&1 | Out-String
            $rc = $LASTEXITCODE
            ShowOut $s.Name $out
            if ($rc -eq 0) { Say "  结果: $($s.Name) → 退出码 0" }
            else { Say "  结果: $($s.Name) → 退出码 $rc"; $c1Fail++ }
        }
        if ($c1Fail -eq 0) { VerdictPass '构建三连全绿（build / vet / test 编译校验均退出码 0）' }
        else { VerdictFail "构建三连有 $c1Fail 步失败（详见上方命令与输出）" }
    }
}

# ================================================================ C2 shell 执行位
Section 'C2' 'shell 脚本执行位（scripts/**.sh 必须为 100755）'
ShowCmd "git ls-files -s scripts/  →  筛出 mode=100644 且路径以 .sh 结尾"
$badSh = @()
foreach ($line in (& git ls-files -s scripts/ 2>$null)) {
    $tabIndex = $line.IndexOf("`t")
    if ($tabIndex -lt 0) { continue }
    $meta = $line.Substring(0, $tabIndex)
    $path = $line.Substring($tabIndex + 1)
    $mode = ($meta -split ' ')[0]
    if ($path -like '*.sh' -and $mode -eq '100644') { $badSh += $path }
}
if ($badSh.Count -eq 0) {
    VerdictPass 'scripts/ 下所有 .sh 均为 100755（可执行位齐备）'
} else {
    ShowOut 'C2' ($badSh -join "`n")
    VerdictFail ("以下 .sh 缺执行位（mode=100644），须 git add --chmod=+x：" + ($badSh -join ' '))
}

# ================================================================ C3 留证工件排除口径
Section 'C3' '留证工件排除口径（docs/verify/crypto/p2-3/*/artifacts/*.go 必须全部带 //go:build ignore）'
if ($docsRel -eq '') {
    VerdictNa '本次检出不含 docs 库（docs 为独立 git 库，主库检出不含 verify/ 留证）→ 未执行（用 -DocsRepo 指定可覆盖）'
} else {
    ShowCmd '逐个读取 artifacts/*.go 首行，判定是否含 //go:build ignore'
    $miss = @(); $total = 0
    $docsRootPath = (Resolve-Path -LiteralPath $docsRel).Path
    $p3 = Join-Path $docsRel 'verify/crypto/p2-3'
    if (Test-Path -LiteralPath $p3) {
        foreach ($f in (Get-ChildItem -LiteralPath $p3 -Filter '*.go' -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.DirectoryName -like '*artifacts*' })) {
            $total++
            $first = (Get-Content -LiteralPath $f.FullName -TotalCount 1 -Encoding UTF8 -ErrorAction SilentlyContinue)
            if ($first -notlike '*//go:build ignore*') {
                $rel = $f.FullName.Substring($docsRootPath.Length + 1).Replace('\', '/')
                $miss += $rel
            }
        }
    }
    Say "  工件 .go 总数: $total"
    if ($total -eq 0) { VerdictNa 'docs 库中未找到 artifacts/*.go（口径不适用）' }
    elseif ($miss.Count -eq 0) { VerdictPass "全部 $total 个工件均带 //go:build ignore（不参与构建 → CI 不会因工件复红）" }
    else {
        ShowOut 'C3' ($miss -join "`n")
        VerdictFail ("以下工件缺 //go:build ignore（会被纳入构建 → CI 复红）：" + ($miss -join ' '))
    }
}

# ================================================================ C4 gofmt 干净度
Section 'C4' 'gofmt 干净度（CRLF 归一化比较；已知漂移走 baseline，新增漂移即 FAIL）'
$baselinePath = 'scripts/check-repo-hygiene.gofmt-baseline.txt'
if (-not (Get-Command gofmt -ErrorAction SilentlyContinue)) {
    VerdictSkip '本机没有 gofmt（无法判定）→ 退出码 2'
    $script:Blockers += ' 缺gofmt'
} else {
    $dirs = @($GofmtDir) + @($ExtraGofmtDir)
    ShowCmd ("gofmt -l " + ($dirs -join ' ') + '  →  再用 CRLF 归一化 diff 过滤假阳性')
    $drift = @(); $gofmtBroken = $false
    foreach ($d in $dirs) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        $listed = & gofmt -l $d 2>$null
        if ($LASTEXITCODE -ne 0) { $gofmtBroken = $true; break }
        foreach ($f in $listed) {
            if (-not (Test-Path -LiteralPath $f)) { continue }
            $formatted = (((& gofmt $f 2>$null) -join "`n") -replace "`r", '')
            if ($LASTEXITCODE -ne 0) { $gofmtBroken = $true; break }
            # 两侧**对称剥离 CR** 后比较：gofmt 会保留源文件换行符（CRLF 输入 → CRLF 输出），
            # 故两边都归一化，否则「仅换行符差异」会被误判为格式漂移（Windows 假阳性）。
            $raw = ((Get-Content -LiteralPath $f -Raw -Encoding UTF8) -replace "`r", '')
            if ($formatted.TrimEnd() -ne $raw.TrimEnd()) {
                $drift += ($f -replace '\\', '/')
            }
        }
        if ($gofmtBroken) { break }
    }
    if ($gofmtBroken) {
        VerdictSkip 'gofmt 调用失败（非 0 退出 / 无法处理路径）→ 无法判定（**不冒充通过**）→ 退出码 2'
        $script:Blockers += ' gofmt调用失败'
    } else {
        $known = @(); $new = @()
        if (Test-Path -LiteralPath $baselinePath) {
            foreach ($line in (Get-Content -LiteralPath $baselinePath -Encoding UTF8)) {
                $t = $line.Trim()
                if ($t -eq '' -or $t.StartsWith('#')) { continue }
                if ($drift -contains $t) { $known += $t } else { $new += $t }
            }
        }
        if ($drift.Count -eq 0) {
            VerdictPass ("检查域内无格式漂移：" + ($dirs -join ' '))
        } else {
            $newDrift = @($drift | Where-Object { $known -notcontains $_ })
            if ($newDrift.Count -eq 0) {
                ShowOut 'C4' ($known -join "`n")
                VerdictPass ("仅存在**已知漂移**（baseline 内，无新增）：" + ($known -join ' '))
                Say '  提示: 已知漂移需由各自域责任人清理；baseline 不得自动扩充（否则会掩盖新增漂移）'
            } else {
                ShowOut 'C4' ($newDrift -join "`n")
                VerdictFail ("存在**新增**格式漂移（不在 baseline）：" + ($newDrift -join ' '))
                if ($known.Count -gt 0) { Say ("  另有已知漂移（baseline 内，不计 FAIL）：" + ($known -join ' ')) }
            }
        }
    }
}

# ================================================================ C5 临时产物未被跟踪
Section 'C5' '临时产物未被跟踪（sag-*.tgz / tmp_* / .probe_tmp/）'
ShowCmd "git ls-files | grep -E '^(sag-.*\.tgz|tmp_|\.probe_tmp/)'"
$hit = @(& git ls-files 2>$null | Where-Object { $_ -match '^(sag-.*\.tgz|tmp_|\.probe_tmp/)' })
if ($hit.Count -eq 0) {
    VerdictPass '无临时产物被跟踪（.gitignore 覆盖生效）'
} else {
    ShowOut 'C5' ($hit -join "`n")
    VerdictFail ("以下临时产物被跟踪（须从索引移除）：" + ($hit -join ' '))
}

# ================================================================ C6 docs 工件未被误提交
Section 'C6' 'docs 工件未被误提交（工件只应作为留证存在于 docs 库，不得进入主库）'
ShowCmd "git ls-files | grep -E '^docs/verify/crypto/p2-3/'   （主库侧）"
$mainHit = @(& git ls-files 2>$null | Where-Object { $_ -match '^docs/verify/crypto/p2-3/' })
$c6Ok = $true
if ($mainHit.Count -gt 0) {
    ShowOut 'C6-主库' ($mainHit -join "`n")
    VerdictFail '主库跟踪了 docs/verify/crypto/p2-3 下的文件（应属 docs 独立库）'
    $c6Ok = $false
}
if ($docsRel -eq '') {
    VerdictNa 'docs 库不在本次检出内 → 未做登记一致性核对'
} elseif ($c6Ok) {
    ShowCmd "git -C <docs> ls-files 'verify/crypto/p2-3/*/artifacts/*'  ⇔ 磁盘工件清单"
    $disk = 0
    $p3 = Join-Path $docsRel 'verify/crypto/p2-3'
    if (Test-Path -LiteralPath $p3) {
        $disk = @(Get-ChildItem -LiteralPath $p3 -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.DirectoryName -like '*artifacts*' }).Count
    }
    $tracked = @(& git -C $docsRel ls-files 'verify/crypto/p2-3/*/artifacts/*' 2>$null).Count
    Say "  磁盘工件文件数: $disk ；docs 库已登记: $tracked"
    if ($disk -ne $tracked) {
        VerdictFail "工件登记与磁盘不一致（磁盘 $disk / 已登记 $tracked）→ 存在漏登记或误提交"
    } else {
        VerdictPass "工件仅作为留证存在于 docs 库，登记数与磁盘一致（$tracked），主库未跟踪"
    }
}

# ---------------------------------------------------------------- 汇总
Rule
Say "汇总: FAIL=$($script:FailCount)  SKIP(无法判定)=$($script:SkipCount)  N/A(不适用)=$($script:NaCount)"
if ($script:Blockers.Count -gt 0) { Say ("环境不满足项:" + ($script:Blockers -join '')) }
Rule
if ($script:FailCount -gt 0) {
    Say "结论: ❌ 存在 $($script:FailCount) 项 FAIL —— 不得作为门禁放行"
    exit 1
}
if ($script:SkipCount -gt 0) {
    Say "结论: ⚠️ 有 $($script:SkipCount) 项无法判定（环境不满足）—— **不冒充通过**，退出码 2"
    exit 2
}
Say '结论: ✅ 全部适用检查通过'
exit 0
