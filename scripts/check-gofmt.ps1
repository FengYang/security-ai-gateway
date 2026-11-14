# check-gofmt.ps1 - Windows local entry point (thin forwarder)
#
# The single implementation moved to scripts/check-gofmt.py on 2026-11-14.
# CI (Linux) and this wrapper both run the SAME logic; this file carries no
# gate logic of its own. Do NOT add logic here -- it would recreate a second
# implementation and let the two drift apart.
#
# Usage: powershell -NoProfile -File scripts/check-gofmt.ps1 -Base origin/master
param(
  [string]$Base = ""
)

$ErrorActionPreference = 'Stop'
$py = $null
foreach ($c in @('python', 'python3')) {
  $cmd = Get-Command $c -ErrorAction SilentlyContinue
  if ($cmd) { $py = $cmd.Source; break }
}
if (-not $py) {
  Write-Host "ERROR: python not found (3.8+ required)" -ForegroundColor Red
  exit 2
}

$target = Join-Path $PSScriptRoot 'check-gofmt.py'
$cliArgs = @($target)
if ($Base -ne "") { $cliArgs += @('--base', $Base) }

& $py @cliArgs
exit $LASTEXITCODE
