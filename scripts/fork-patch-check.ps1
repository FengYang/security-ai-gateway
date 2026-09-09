# fork-patch-check.ps1 - Vendor-fork whitelist guard + patch exporter.
#
# Enforces "add-only, whitelist-controlled" customization (docs/管理门户-细化方案.md 2.2):
#   1. No upstream-tracked file may be deleted or renamed.
#   2. Upstream-tracked files that ARE modified must be listed in
#      fork-patches/higress-console/whitelist-upstream.txt (menu/locale/route
#      registration points only).
#   3. Brand-new files are unrestricted (add-only by design).
# On success it regenerates fork-patches/higress-console/higress-console-custom.patch
# from <baseline>..HEAD so the fork stays rebuildable from a clean upstream clone
# (the fork directory itself is git-ignored in the main repo, vendor/).
#
# Usage:
#   pwsh -File scripts/fork-patch-check.ps1            # defaults below
#   pwsh -File scripts/fork-patch-check.ps1 -ForkRoot <path> [-BaseRev <rev>]
# Exit code: 0 = pass (patch exported), 1 = whitelist violation / error.

param(
    [string]$ForkRoot = (Join-Path $PSScriptRoot '..\vendor\higress-console'),
    [string]$BaseRev = '',
    [string]$PatchOutDir = (Join-Path $PSScriptRoot '..\fork-patches\higress-console')
)

$ErrorActionPreference = 'Stop'

function Fail([string]$msg) {
    Write-Error $msg
    exit 1
}

# Resolve absolute fork root (must be a git working tree). Use .Path string so
# native git receives a plain path (PathInfo objects can confuse argument binding).
$Fork = (Resolve-Path $ForkRoot -ErrorAction SilentlyContinue)
if (-not $Fork) { Fail "Fork root not found: $ForkRoot" }
$Fork = $Fork.Path

# ---- baseline -------------------------------------------------------------
if (-not $BaseRev) {
    $baselineFile = Join-Path $PatchOutDir 'baseline.txt'
    if (-not (Test-Path $baselineFile)) { Fail "baseline.txt not found under $PatchOutDir" }
    foreach ($line in Get-Content $baselineFile) {
        if ($line -and -not $line.StartsWith('#')) { $BaseRev = $line.Trim(); break }
    }
}
if (-not $BaseRev) { Fail 'Could not determine baseline revision.' }
git -C $Fork cat-file -e "$BaseRev^{commit}" 2>$null
if ($LASTEXITCODE -ne 0) {
    Fail "Baseline revision not present in fork: $BaseRev (fetch origin first)"
}

# Fork working tree must be clean so the exported patch matches HEAD exactly.
$dirty = git -C $Fork status --porcelain
if ($dirty) {
    Fail 'Fork working tree is dirty. Commit (or restore) changes before exporting the patch.'
}

# ---- whitelist ------------------------------------------------------------
$whitelistFile = Join-Path $PatchOutDir 'whitelist-upstream.txt'
if (-not (Test-Path $whitelistFile)) { Fail "whitelist-upstream.txt not found under $PatchOutDir" }
$allowed = @{}
foreach ($line in Get-Content $whitelistFile) {
    if ($line -and -not $line.StartsWith('#')) { $allowed[$line.Trim().Replace('\', '/')] = $true }
}

# ---- audit diff vs baseline -----------------------------------------------
# Quote the rev range: an unquoted `$BaseRev..HEAD` makes PowerShell try member
# access on the variable and mangles the argument passed to git.
$revRange = "$BaseRev..HEAD"
$lines = git -C $Fork diff --name-status $revRange
if ($LASTEXITCODE -ne 0) { Fail "git diff failed for $revRange" }
if (-not $lines) { Fail "No customization found between $BaseRev and HEAD." }

$violations = @()
foreach ($raw in $lines) {
    $raw = $raw.Trim()
    if (-not $raw) { continue }
    $status = $raw.Substring(0, [Math]::Min(1, $raw.Length))
    $file = $raw.Substring(2).Trim()
    switch ($status) {
        'A' { break }  # add-only: unrestricted
        'M' {
            if (-not $allowed.ContainsKey($file)) {
                $violations += "MODIFIED upstream file not in whitelist: $file"
            }
            break
        }
        default {
            $violations += "FORBIDDEN status '$status' (delete/rename/copy of upstream file): $file"
        }
    }
}

if ($violations.Count -gt 0) {
    Write-Output 'Whitelist VIOLATIONS:'
    $violations | ForEach-Object { Write-Output "  $_" }
    exit 1
}

# ---- export patch ----------------------------------------------------------
# Use `git diff --output` (byte-faithful, keeps UTF-8 content in translation.json)
# instead of piping through PowerShell which would re-encode the stream.
New-Item -ItemType Directory -Force -Path $PatchOutDir | Out-Null
$patchFile = Join-Path $PatchOutDir 'higress-console-custom.patch'
git -C $Fork diff --binary $revRange --output=$patchFile
if ($LASTEXITCODE -ne 0) { Fail 'Failed to export patch.' }

$stat = git -C $Fork diff --stat $revRange
Write-Output "PASS: fork customization is whitelist-compliant (base=$BaseRev)."
Write-Output "Patch exported: $patchFile"
Write-Output $stat
exit 0
