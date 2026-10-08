# check-gofmt.ps1 - Incremental gofmt gate.
#
# Purpose: fail CI when newly added/modified .go files are not gofmt-clean.
# Rationale: the repository still carries legacy gofmt drift in several packages,
# so a full-repo check would fail today; this gate only checks the .go files that
# changed in the current change set (base..HEAD). Once the whole tree is clean the
# gate can be widened to a full-repo check.
#
# Usage:
#   pwsh -NoProfile -File scripts/check-gofmt.ps1 -Base origin/master
#   pwsh -NoProfile -File scripts/check-gofmt.ps1 -Base HEAD^
param(
  [string]$Base = ""
)
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

# Diff range: explicit base (PR base / previous commit) when provided, else HEAD^.
$range = if ($Base -ne "") { "$Base...HEAD" } else { "HEAD^...HEAD" }
$changed = & git diff --name-only $range -- '*.go' 2>$null
$files = @($changed | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
if ($files.Count -eq 0) {
  Write-Host "gofmt gate: no changed .go files in '$range'; skip."
  exit 0
}

$bad = @(& gofmt -l $files)
if ($bad.Count -gt 0) {
  Write-Host "gofmt gate FAIL: the following changed .go files are not gofmt-clean:"
  $bad | ForEach-Object { Write-Host "  $_" }
  Write-Host "Fix locally with: gofmt -w <files>"
  exit 1
}
Write-Host "gofmt gate PASS: $($files.Count) changed .go file(s) are gofmt-clean."
exit 0
