# canary-release.ps1 - Windows local entry point (thin forwarder)
#
# The single implementation moved to scripts/canary-release.py on 2026-11-14.
# CI (Linux) and this wrapper both run the SAME logic; this file carries no
# logic of its own. Do NOT add logic here -- it would recreate a second
# implementation and let the two drift apart.
#
# Usage (unchanged from the original parameter names):
#   powershell -File scripts/canary-release.ps1 -Action deploy  -Tag v2.0.0
#   powershell -File scripts/canary-release.ps1 -Action weight  -Canary 1 -Stable 2
#   powershell -File scripts/canary-release.ps1 -Action promote -Tag v2.0.0
#   powershell -File scripts/canary-release.ps1 -Action rollback -Tag v1.0.0
#   powershell -File scripts/canary-release.ps1 -Action status
#   powershell -File scripts/canary-release.ps1 -Action deploy -Tag v2.0.0 -DryRun
param(
    [ValidateSet('deploy', 'weight', 'promote', 'rollback', 'status')]
    [string]$Action,
    [string]$Tag = 'latest',
    [int]$Canary = 1,
    [int]$Stable = 2,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$py = $null
foreach ($c in @('python', 'python3')) {
  $cmd = Get-Command $c -ErrorAction SilentlyContinue
  if ($cmd) { $py = $cmd.Source; break }
}
if (-not $py) { throw 'python not found (3.8+ required)' }

$cliArgs = @((Join-Path $PSScriptRoot 'canary-release.py'), $Action,
             '--tag', $Tag, '--canary', "$Canary", '--stable', "$Stable")
if ($DryRun) { $cliArgs += '--dry-run' }

& $py @cliArgs
exit $LASTEXITCODE
