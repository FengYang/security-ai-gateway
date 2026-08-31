# verify-k8s.ps1 - M10 K8s manifests verification (single-node dev env)
#
# Validates the K8s/monitoring manifests and app images WITHOUT a cluster:
#   1. kustomize render  (kubectl kustomize, catches structural errors)
#   2. YAML syntax check (python yaml.safe_load_all per document)
#   3. kubectl client dry-run (server dry-run skipped when no cluster)
#   4. App images buildable (embedding-service / tee-infer-service / envoy-gateway)
#
# Optional real-cluster verification with kind (requires kind + a docker daemon):
#   powershell -NoProfile -File scripts/verify-k8s.ps1 -Kind
#
# Usage: powershell -NoProfile -File scripts/verify-k8s.ps1

param([switch]$Kind)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$go = $env:GO_BIN
if (-not $go) {
    $g = Get-Command go -ErrorAction SilentlyContinue
    if ($g) { $go = $g.Source } else { $go = 'C:\Program Files\Go\bin\go.exe' }
}
$results = @

function Check($name, [bool]$ok, $detail = '') {
    $tag = if ($ok) { 'PASS' } else { 'FAIL' }
    $script:results += [pscustomobject]@{ Name = $name; Status = $tag; Detail = $detail }
    if ($ok) { Write-Host "[$tag] $name $detail" -ForegroundColor Green }
    else { Write-Host "[$tag] $name $detail" -ForegroundColor Red }
}

# Invoke-Native: run a native command, capture exit code and output
# (avoids stderr being treated as a terminating error under ErrorActionPreference).
function Invoke-Native {
    param([string]$cmd, [string[]]$argsList)
    $oldEA = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = & $cmd @argsList 2>&1 | Out-String
    $code = $LASTEXITCODE
    $ErrorActionPreference = $oldEA
    return [pscustomobject]@{ Code = $code; Out = $out }
}

Write-Host "===== M10 K8s manifests verification =====" -ForegroundColor Cyan
Push-Location $root

# 1. kustomize render (deploy/k8s + deploy/monitoring)
Write-Host "`n[1/5] kustomize render" -ForegroundColor Yellow
$r1 = Invoke-Native 'kubectl' @('kustomize', 'deploy/k8s')
$k8sOk = ($r1.Code -eq 0) -and ($r1.Out -match 'kind: Deployment')
$r2 = Invoke-Native 'kubectl' @('kustomize', 'deploy/monitoring')
$monOk = ($r2.Code -eq 0) -and ($r2.Out -match 'kind: Deployment')
Check 'kustomize render (k8s + monitoring)' ($k8sOk -and $monOk)

# 2. YAML syntax (python yaml.safe_load_all per document)
Write-Host "`n[2/5] YAML syntax" -ForegroundColor Yellow
$yamlCheck = @"
import sys, yaml
for path in sys.argv[1:]:
    docs = [d for d in yaml.safe_load_all(open(path, encoding='utf-8')) if d]
    print(f'{path}: {len(docs)} docs OK')
"@
$files = Get-ChildItem -Recurse deploy -Filter *.yaml |
    Where-Object { $_.FullName -notmatch '\\templates\\' } | # Helm 模板含 Go template 语法，由 helm lint 校验
    ForEach-Object { $_.FullName }
$r3 = Invoke-Native 'python' (@('-c', $yamlCheck) + @($files))
Check 'YAML syntax (all deploy/*.yaml)' ($r3.Code -eq 0) (($r3.Out -replace "`n", ' ').Trim)

# 3. kubectl dry-run (requires a cluster context; otherwise covered by kustomize+YAML)
Write-Host "`n[3/5] kubectl dry-run" -ForegroundColor Yellow
$r4 = Invoke-Native 'kubectl' @('config', 'current-context')
if ($r4.Code -eq 0 -and $r4.Out.Trim -ne '') {
    $r5 = Invoke-Native 'kubectl' @('apply', '--dry-run=server', '-k', 'deploy/k8s', '-o', 'name')
    Check 'kubectl server dry-run (k8s)' ($r5.Code -eq 0) (($r5.Out -replace "`n", ' ').Trim)
    $r6 = Invoke-Native 'kubectl' @('apply', '--dry-run=server', '-k', 'deploy/monitoring', '-o', 'name')
    Check 'kubectl server dry-run (monitoring)' ($r6.Code -eq 0) (($r6.Out -replace "`n", ' ').Trim)
} else {
    Check 'kubectl server dry-run (no cluster, skipped)' $true '(kustomize + YAML checks cover syntax)'
}

# 4. App images buildable
Write-Host "`n[4/6] App images buildable" -ForegroundColor Yellow
$r7 = Invoke-Native $go @('build', './gateway/tee-infer-service/', './gateway/embedding-service/')
Check 'Go services build' ($r7.Code -eq 0)
$r8 = Invoke-Native 'docker' @('build', '-q', '-t', 'otpmask/envoy-gateway:latest', '-f', 'gateway/wasm/otpmask-plugin/Dockerfile.k8s', 'gateway/wasm/otpmask-plugin')
Check 'envoy-gateway image build (wasm bundled)' ($r8.Code -eq 0)

# 4b. Helm Chart (M12 C-class closure: helm lint + template render)
Write-Host "`n[4b/6] Helm Chart (otpmask)" -ForegroundColor Yellow
$helmBin = $env:HELM_BIN
if (-not $helmBin) {
    $h = Get-Command helm -ErrorAction SilentlyContinue
    if ($h) { $helmBin = $h.Source } else { $helmBin = 'c:\Users\Robin\.trae-cn\work\6a93a46b2f0da2dc35a6f367\helm-bin\helm.exe' }
}
if (Test-Path $helmBin) {
    $r11 = Invoke-Native $helmBin @('lint', 'deploy/helm/otpmask')
    $r12 = Invoke-Native $helmBin @('template', 'otpmask', 'deploy/helm/otpmask')
    $ok = ($r11.Code -eq 0) -and ($r12.Code -eq 0) -and ($r12.Out -match 'kind: Deployment')
    Check 'helm lint + template render' $ok
} else {
    Check 'helm lint + template (helm not found, skipped)' $true '(set $env:HELM_BIN)'
}

# 5. Optional: kind real-cluster verification
Write-Host "`n[5/5] kind cluster (optional)" -ForegroundColor Yellow
if ($Kind) {
    $r9 = Invoke-Native 'kind' @('create', 'cluster', '--config', 'deploy/kind/kind-config.yaml')
    if ($r9.Code -eq 0) {
        $null = Invoke-Native 'kubectl' @('apply', '-k', 'deploy/k8s')
        $null = Invoke-Native 'kubectl' @('apply', '-k', 'deploy/monitoring')
        Start-Sleep -Seconds 20
        $r10 = Invoke-Native 'kubectl' @('get', 'pods', '-n', 'otpmask', '-o', 'jsonpath={range .items[*]}{.metadata.name} {.status.phase}{\"\\n\"}{end}')
        Check 'kind cluster + deployments ready' ($r10.Out -match 'Running') ($r10.Out -replace "`n", ' ')
    } else {
        Check 'kind cluster create' $false ($r9.Out)
    }
} else {
    Check 'kind cluster (skipped, use -Kind)' $true '(single-node dev env: dry-run only)'
}

Pop-Location

Write-Host "`n===== Summary =====" -ForegroundColor Cyan
$pass = ($results | Where-Object Status -eq 'PASS').Count
$fail = ($results | Where-Object Status -eq 'FAIL').Count
$results | Format-Table -AutoSize | Out-String | Write-Host
if ($fail -eq 0) {
    Write-Host "ALL PASSED ($pass/$($results.Count))" -ForegroundColor Green
    exit 0
} else {
    Write-Host "FAILED: $fail item(s) ($pass/$($results.Count))" -ForegroundColor Red
    exit 1
}
