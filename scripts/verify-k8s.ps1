# verify-k8s.ps1 - Windows local entry point (thin forwarder)
#
# The single implementation moved to scripts/verify-k8s.py on 2026-11-14.
# CI (Linux) and this wrapper both run the SAME logic; this file carries no
# gate logic of its own. Do NOT add logic here -- it would recreate a second
# implementation and let the two drift apart.
#
# Usage:
#   powershell -NoProfile -File scripts/verify-k8s.ps1
#   powershell -NoProfile -File scripts/verify-k8s.ps1 -Kind
param([switch]$Kind)

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

$cliArgs = @((Join-Path $PSScriptRoot 'verify-k8s.py'))
if ($Kind) { $cliArgs += '--kind' }

& $py @cliArgs
exit $LASTEXITCODE
