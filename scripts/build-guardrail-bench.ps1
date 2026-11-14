# build-guardrail-bench.ps1 - Windows local entry point (thin forwarder)
#
# The single implementation moved to scripts/build-guardrail-bench.py on 2026-11-14.
# CI (Linux) and this wrapper both run the SAME logic; this file carries no logic
# of its own. Do NOT add logic here -- it would recreate a second implementation
# and let the two drift apart.
#
# Usage (parameter names unchanged from the original script):
#   powershell -ExecutionPolicy Bypass -File scripts/build-guardrail-bench.ps1
#   powershell -ExecutionPolicy Bypass -File scripts/build-guardrail-bench.ps1 `
#       -PublicSource raw -HfEndpoint https://hf-mirror.com `
#       -PythonExe .tools\bench-py\Scripts\python.exe
param(
    [string]$OutDir = '',
    [int]$AttackPerSet = 50,
    [int]$BenignPerSet = 30,
    [ValidateSet('rows', 'raw')][string]$PublicSource = 'rows',
    [string]$HfEndpoint = 'https://huggingface.co',
    [string]$DatasetsServer = 'https://datasets-server.huggingface.co',
    [string]$PythonExe = ''
)

$ErrorActionPreference = 'Stop'
$py = $null
foreach ($c in @('python', 'python3')) {
  $cmd = Get-Command $c -ErrorAction SilentlyContinue
  if ($cmd) { $py = $cmd.Source; break }
}
if (-not $py) { throw 'python not found (3.8+ required)' }

$cliArgs = @((Join-Path $PSScriptRoot 'build-guardrail-bench.py'),
  '--attack-per-set', "$AttackPerSet",
  '--benign-per-set', "$BenignPerSet",
  '--public-source', $PublicSource,
  '--hf-endpoint', $HfEndpoint,
  '--datasets-server', $DatasetsServer)

if ($OutDir -ne '')    { $cliArgs += @('--out-dir', $OutDir) }
if ($PythonExe -ne '') { $cliArgs += @('--python-exe', $PythonExe) }

& $py @cliArgs
exit $LASTEXITCODE
