# verify-all.ps1 - Windows local entry point (thin forwarder)
#
# The single implementation moved to scripts/verify-all.py on 2026-11-14.
# CI (Linux self-hosted runner) and this wrapper both run the SAME 23 checks;
# this file carries no check logic of its own. Do NOT add logic here -- it would
# recreate a second implementation and let the two drift apart.
#
# Usage:
#   powershell -NoProfile -File scripts/verify-all.ps1
#
# Environment:
#   GO_BIN      - path to go (defaults to PATH lookup)
#   PYTHON_BIN  - path to python (defaults to PATH lookup)
#
# Exit code: 0 = all checks passed; 1 = at least one failed.

$ErrorActionPreference = 'Stop'
$py = $null
foreach ($c in @('python', 'python3')) {
  $cmd = Get-Command $c -ErrorAction SilentlyContinue
  if ($cmd) { $py = $cmd.Source; break }
}
if (-not $py) {
  Write-Host "ERROR: python not found (3.8+ required)" -ForegroundColor Red
  exit 1
}

& $py (Join-Path $PSScriptRoot 'verify-all.py')
exit $LASTEXITCODE
