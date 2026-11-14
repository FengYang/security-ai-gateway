# check-metrics-green.ps1 - Windows local entry point (thin forwarder)
#
# The single implementation moved to scripts/check-metrics-green.py on 2026-11-14.
# CI (Linux) and this wrapper both run the SAME logic; this file carries no gate
# logic of its own. Do NOT add logic here -- it would recreate a second
# implementation and let the two drift apart.
#
# Usage (parameter names unchanged from the original script):
#   powershell -ExecutionPolicy Bypass -File scripts/check-metrics-green.ps1
#   ... -Tee http://127.0.0.1:19090 -TeeToken <token> -Admin http://127.0.0.1:19095
#       -Core http://127.0.0.1:8085 -CoreToken <OTP_CORE_AUTH_TOKEN>
#       -Container higress-chain-control-plane
#   Exit code: 0 = all required metrics present; 1 = FAIL; 2 = script/environment error
param(
    [string]$Tee = 'http://127.0.0.1:19090',
    [string]$TeeToken = '',
    [string]$Admin = 'http://127.0.0.1:19095',
    [string]$Core = 'http://127.0.0.1:8085',
    [string]$CoreToken = '',
    [string]$Cryptop = 'http://127.0.0.1:19097',
    [string]$A2a = 'http://127.0.0.1:19099',
    [string]$Container = 'higress-chain-control-plane',
    [string]$Manifest = '',
    [int]$TimeoutSec = 15,
    [switch]$SkipTee,
    [switch]$SkipAdmin,
    [switch]$SkipCore,
    [switch]$SkipPlugin,
    [switch]$SkipCryptop,
    [switch]$SkipA2a,
    [switch]$RequireAllSources
)

$ErrorActionPreference = 'Stop'
$py = $null
foreach ($c in @('python', 'python3')) {
  $cmd = Get-Command $c -ErrorAction SilentlyContinue
  if ($cmd) { $py = $cmd.Source; break }
}
if (-not $py) {
  Write-Host "清单/环境错误: python not found (3.8+ required)" -ForegroundColor Red
  exit 2
}

$cliArgs = @((Join-Path $PSScriptRoot 'check-metrics-green.py'),
  '--tee', $Tee, '--tee-token', $TeeToken,
  '--admin', $Admin,
  '--core', $Core, '--core-token', $CoreToken,
  '--cryptop', $Cryptop,
  '--a2a', $A2a,
  '--container', $Container,
  '--timeout', "$TimeoutSec")

if ($Manifest -ne '') { $cliArgs += @('--manifest', $Manifest) }
if ($SkipTee)    { $cliArgs += '--skip-tee' }
if ($SkipAdmin)  { $cliArgs += '--skip-admin' }
if ($SkipCore)   { $cliArgs += '--skip-core' }
if ($SkipPlugin) { $cliArgs += '--skip-plugin' }
if ($SkipCryptop){ $cliArgs += '--skip-cryptop' }
if ($SkipA2a)    { $cliArgs += '--skip-a2a' }
if ($RequireAllSources) { $cliArgs += '--require-all-sources' }

& $py @cliArgs
exit $LASTEXITCODE
