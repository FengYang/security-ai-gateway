# build-console-frontend.ps1 - Build the vendor-forked Higress console frontend.
#
# Why this script exists (docs/管理门户-细化方案.md 7.4 L1):
#   The frontend CANNOT be built inside the main repo working tree because the
#   repo path contains non-ASCII chars (方案) and ICE/webpack rejects assets that
#   are "not in cwd". It also cannot be built in place at C:\higress-v0 under the
#   Trae sandbox (writes outside the workspace are blocked). Solution verified on
#   2026-09-10: robocopy the frontend (node_modules included) to an ASCII temp dir
#   and run `npm run build` there. Output = $BuildDir\frontend\build.
#
# Usage:
#   pwsh -File scripts/build-console-frontend.ps1
#   pwsh -File scripts/build-console-frontend.ps1 -ForkRoot <abs> -BuildDir <abs>
# Exit code: 0 = build ok, 1 = failure.
#
# NOTE: never exclude directories by the name "node" during the copy - deps such
# as @babel/generator/lib/node exist and would be silently dropped (lesson learned).

param(
    [string]$ForkRoot = (Join-Path $PSScriptRoot '..\vendor\higress-console'),
    [string]$BuildDir = (Join-Path $env:TEMP 'console-build')
)

$ErrorActionPreference = 'Stop'

function Fail([string]$msg) {
    Write-Error $msg
    exit 1
}

$fork = (Resolve-Path $ForkRoot -ErrorAction SilentlyContinue)
if (-not $fork) { Fail "Fork root not found: $ForkRoot" }
$fork = $fork.Path

$srcFrontend = Join-Path $fork 'frontend'
if (-not (Test-Path $srcFrontend)) { Fail "Frontend not found: $srcFrontend" }

# Bundled node runtime downloaded by V0 under frontend/node.
$nodeDir = Join-Path $srcFrontend 'node'
if (-not (Test-Path (Join-Path $nodeDir 'node.exe'))) {
    Fail "Bundled node not found under $nodeDir (run frontend npm install once / or provide node on PATH)"
}
$npmCmd = Join-Path $nodeDir 'npm.cmd'

# ---- stage to an ASCII build dir ------------------------------------------
$buildFrontend = Join-Path $BuildDir 'frontend'
if (Test-Path $buildFrontend) { Remove-Item -Recurse -Force $buildFrontend }
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

# Copy EVERYTHING except .husky. Do not pass /XD node (would drop dep dirs named
# "node", e.g. @babel/generator/lib/node). Exit code <8 means success for robocopy.
robocopy $srcFrontend $buildFrontend /E /XD .husky /MT:16 /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { Fail "robocopy failed with exit code $LASTEXITCODE" }

# ---- build (production) ----------------------------------------------------
$oldPath = $env:Path
try {
    $env:Path = "$nodeDir;$env:Path"
    Push-Location $buildFrontend
    try {
        & $npmCmd 'run' 'build'
    } finally {
        Pop-Location
    }
} finally {
    $env:Path = $oldPath
}
if ($LASTEXITCODE -ne 0) { Fail "npm run build failed with exit code $LASTEXITCODE" }

$out = Join-Path $buildFrontend 'build'
if (-not (Test-Path (Join-Path $out 'index.html'))) {
    Fail "Build output missing index.html at $out"
}
Write-Output "PASS: console frontend built successfully."
Write-Output "Build output: $out"
exit 0
