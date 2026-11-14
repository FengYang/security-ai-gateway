# check-higress-plugin-versions.ps1 - Windows local entry point (thin forwarder)
#
# The single implementation moved to scripts/check-higress-plugin-versions.py on
# 2026-11-14. CI (Linux) and this wrapper both run the SAME logic; this file
# carries no gate logic of its own. Do NOT add logic here -- it would recreate a
# second implementation and let the two drift apart.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts/check-higress-plugin-versions.ps1
#   powershell -ExecutionPolicy Bypass -File scripts/check-higress-plugin-versions.ps1 -Container higress-chain-control-plane
param(
    [string]$LockFile = '',
    [string]$Root = '',
    [string]$Container = ''
)

$ErrorActionPreference = 'Stop'
$py = $null
foreach ($c in @('python', 'python3')) {
  $cmd = Get-Command $c -ErrorAction SilentlyContinue
  if ($cmd) { $py = $cmd.Source; break }
}
if (-not $py) {
  Write-Output "[FAIL] python not found (3.8+ required)"
  exit 2
}

$cliArgs = @((Join-Path $PSScriptRoot 'check-higress-plugin-versions.py'))
if ($LockFile -ne '') { $cliArgs += @('--lock-file', $LockFile) }
if ($Root -ne '')     { $cliArgs += @('--root', $Root) }
if ($Container -ne '') { $cliArgs += @('--container', $Container) }

& $py @cliArgs
exit $LASTEXITCODE
