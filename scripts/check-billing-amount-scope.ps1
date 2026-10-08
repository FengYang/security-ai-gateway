# check-billing-amount-scope.ps1 - P0-3 T-4.3-4: money columns are ONLY on the billing page.
#
# Scans the (patched) console fork and fails if money-rendering tokens appear outside
#   - frontend/src/pages/admin-ext/billing/
#   - frontend/src/services/admin-ext-billing.ts
# Rationale: design §3.1.3 / M10 - amount columns are confined to the billing domain page.
# The console has no JS test runner, so this source scan is the CI-enforced contract
# (same spirit as the tee-infer S-3 field scan).
#
# Usage: pwsh -NoProfile -File scripts/check-billing-amount-scope.ps1 [-ForkRoot <path>]
# Exit: 0 = pass (or fork tree absent -> skip); 1 = violation.
param(
  [string]$ForkRoot = (Join-Path $PSScriptRoot '..\vendor\higress-console')
)
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path $ForkRoot -ErrorAction SilentlyContinue)
if (-not $root) { Write-Host "amount-scope gate: fork root not found ($ForkRoot); skip."; exit 0 }
$src = Join-Path $root 'frontend\src'
if (-not (Test-Path -LiteralPath $src)) { Write-Host 'amount-scope gate: frontend/src not found; skip.'; exit 0 }

# Money-rendering tokens that must be confined to the billing page/service.
$tokens = @('fenToYuan', 'amountFen')
$allowDirs = @(Join-Path $src 'pages\admin-ext\billing')
$allowFiles = @((Join-Path $src 'services\admin-ext-billing.ts'))

$dirs = @((Join-Path $src 'pages\admin-ext'), (Join-Path $src 'services')) | Where-Object { Test-Path -LiteralPath $_ }
$files = @()
foreach ($d in $dirs) {
  $files += Get-ChildItem -LiteralPath $d -Recurse -File | Where-Object { $_.Extension -eq '.ts' -or $_.Extension -eq '.tsx' }
}

$violations = @()
foreach ($f in $files) {
  $skip = $false
  foreach ($a in $allowDirs) { if ($f.FullName.StartsWith($a, [System.StringComparison]::OrdinalIgnoreCase)) { $skip = $true; break } }
  if (-not $skip) { foreach ($a in $allowFiles) { if ($f.FullName -eq $a) { $skip = $true; break } } }
  if ($skip) { continue }
  $text = Get-Content -LiteralPath $f.FullName -Raw
  foreach ($tk in $tokens) {
    if ($text -like "*$tk*") { $violations += ($f.FullName + " contains '" + $tk + "'") }
  }
}

if ($violations.Count -gt 0) {
  Write-Host 'amount-scope gate FAIL: money tokens found outside the billing page:'
  $violations | ForEach-Object { Write-Host ('  ' + $_) }
  exit 1
}
Write-Host 'amount-scope gate PASS: money tokens are confined to the billing page/service.'
exit 0
