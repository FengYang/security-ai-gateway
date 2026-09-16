# deploy-og11-k3s.ps1 - OG-11: tee-infer-service shadow + Phala C-MaaS deploy to LAN K3s
#
# Stages (default = all in order):
#   -Stage build    build linux/amd64 image locally + docker save tar
#   -Stage upload   sftp tar to K3s node + k3s ctr images import
#                   (needs env K3S_HOST / K3S_USER / K3S_PW, consumed by .tools/k3s-ssh.py)
#   -Stage secret   create/replace Secret otpmask-cmaas from deploy/secrets/cmaas.env
#   -Stage rollout  kubectl apply deployment + rollout wait + /config and /metrics acceptance
#
# Example:
#   $env:K3S_HOST='192.168.31.166'; $env:K3S_USER='feng'; $env:K3S_PW='***'
#   powershell -NoProfile -File scripts/deploy-og11-k3s.ps1
#   powershell -NoProfile -File scripts/deploy-og11-k3s.ps1 -Stage upload

param(
    [ValidateSet('all', 'build', 'upload', 'secret', 'rollout')]
    [string]$Stage = 'all'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$image = 'otpmask/tee-infer-service:og11'
# PS 5.1 Join-Path only accepts two arguments; pre-join nested paths here.
$tarAbs = Join-Path $root '.tools\k3s-images\tee-infer-og11.tar'
$sshPy = Join-Path $root '.tools\k3s-ssh.py'
$kubeconfig = Join-Path $root '.tools\k3s-kubeconfig.yaml'
$cmaasEnv = Join-Path $root 'deploy\secrets\cmaas.env'
$deployYaml = Join-Path $root 'deploy\k8s\tee-infer-service.yaml'
$ns = 'otpmask'
$pfPort = 19191

function Write-Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Assert-Native($desc) {
    if ($LASTEXITCODE -ne 0) { throw "$desc failed (exit=$LASTEXITCODE)" }
}

# ---------- build ----------
function Stage-Build {
    Write-Step 'build: docker build (linux/amd64) + save'
    Push-Location $root
    try {
        docker build --platform linux/amd64 -t $image -f gateway/tee-infer-service/Dockerfile .
        Assert-Native 'docker build'
        docker save -o $tarAbs $image
        Assert-Native 'docker save'
        Write-Host "[build] saved -> $tarAbs ($([math]::Round((Get-Item $tarAbs).Length / 1MB, 1)) MB)" -ForegroundColor Green
    } finally {
        Pop-Location
    }
}

# ---------- upload ----------
function Stage-Upload {
    Write-Step 'upload: sftp put + k3s ctr images import'
    foreach ($v in 'K3S_HOST', 'K3S_USER', 'K3S_PW') {
        if (-not [Environment]::GetEnvironmentVariable($v)) { throw "missing env $v" }
    }
    if (-not (Test-Path $tarAbs)) { throw "image tar not found: $tarAbs (run -Stage build first)" }

    python -c 'import paramiko' 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host '[upload] installing paramiko ...'
        python -m pip install --quiet paramiko
        Assert-Native 'pip install paramiko'
    }

    $remote = '/tmp/tee-infer-og11.tar'
    Write-Host "[upload] sftp put -> $($env:K3S_HOST):$remote"
    python $sshPy put $tarAbs $remote
    Assert-Native 'sftp put'

    # Prefer passwordless sudo; fall back to password pipe (not written to remote disk).
    $probe = python $sshPy run 'sudo -n true 2>/dev/null && echo NOPASS || echo NEEDPW'
    Assert-Native 'sudo probe'
    if ($probe -match 'NEEDPW') {
        Write-Host '[upload] sudo requires password (using env K3S_PW)'
        python $sshPy run "echo $($env:K3S_PW) | sudo -S k3s ctr images import $remote"
        Assert-Native 'k3s ctr images import (sudo -S)'
        python $sshPy run "echo $($env:K3S_PW) | sudo -S k3s ctr images ls | grep tee-infer-service"
        Assert-Native 'image verify'
    } else {
        python $sshPy run "sudo k3s ctr images import $remote"
        Assert-Native 'k3s ctr images import'
        python $sshPy run 'sudo k3s ctr images ls | grep tee-infer-service'
        Assert-Native 'image verify'
    }
    python $sshPy run "rm -f $remote"
    Assert-Native 'remote cleanup'
    Write-Host '[upload] image imported on node' -ForegroundColor Green
}

# ---------- secret ----------
function Stage-Secret {
    Write-Step 'secret: otpmask-cmaas from deploy/secrets/cmaas.env'
    if (-not (Test-Path $cmaasEnv)) { throw "missing $cmaasEnv" }
    $cfg = @{}
    Get-Content $cmaasEnv -Encoding UTF8 | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith('#')) {
            $kv = $line -split '=', 2
            if ($kv[0] -and $kv[1]) { $cfg[$kv[0].Trim()] = $kv[1].Trim() }
        }
    }
    if (-not $cfg['CMAAS_URL'] -or -not $cfg['CMAAS_API_KEY']) { throw 'CMAAS_URL / CMAAS_API_KEY required in cmaas.env' }

    $env:KUBECONFIG = $kubeconfig
    $env:KUBECACHEDIR = Join-Path $env:TEMP 'k8s-cache-og'

    $yaml = kubectl create secret generic otpmask-cmaas -n $ns `
        --from-literal=url=$($cfg['CMAAS_URL']) `
        --from-literal=model=$($cfg['CMAAS_MODEL']) `
        --from-literal=api-key=$($cfg['CMAAS_API_KEY']) `
        --dry-run=client -o yaml
    Assert-Native 'render secret'
    $yaml | kubectl apply -f -
    Assert-Native 'apply secret'
    Write-Host '[secret] otpmask-cmaas applied (keys: url/model/api-key; value redacted)' -ForegroundColor Green
}

# ---------- rollout ----------
function Stage-Rollout {
    Write-Step 'rollout: apply deployment + wait + acceptance'
    $env:KUBECONFIG = $kubeconfig
    $env:KUBECACHEDIR = Join-Path $env:TEMP 'k8s-cache-og'

    kubectl apply -f $deployYaml
    Assert-Native 'kubectl apply'
    kubectl -n $ns rollout status deploy/tee-infer-service --timeout=180s
    Assert-Native 'rollout status'

    # -notmatch on an ARRAY filters elements instead of negating; join to a single string first.
    $logs = (kubectl -n $ns logs deploy/tee-infer-service --tail=80) -join "`n"
    if ($logs -notmatch 'policy_version=pv2026\.09\.16') { throw 'startup log missing policy load line' }
    # ASCII-only assertion: the shadow startup log line uniquely contains "off/shadow"
    # (Chinese in this file would break PS 5.1 without BOM).
    if ($logs -notmatch 'off/shadow') { throw 'startup log missing shadow mode line' }
    Write-Host '[accept] startup log: policy pv2026.09.16 loaded + shadow mode' -ForegroundColor Green

    # Port-forward for in-cluster service acceptance (same kubeconfig).
    $pf = Start-Process -FilePath 'kubectl' -ArgumentList @(
        '-n', $ns, 'port-forward', 'deploy/tee-infer-service', "$($pfPort):19090"
    ) -NoNewWindow -PassThru -RedirectStandardError (Join-Path $env:TEMP 'og11-pf.err')
    try {
        Start-Sleep -Seconds 4
        $cfg = Invoke-RestMethod "http://127.0.0.1:$pfPort/config" -TimeoutSec 10
        $og = $cfg.output_guard
        if ($og.mode -ne 'shadow') { throw "config mode=$($og.mode), want shadow" }
        if ($og.policy_version -ne 'pv2026.09.16') { throw "config policy_version=$($og.policy_version)" }
        if ($og.l1_categories_loaded -ne 30) { throw "l1_categories_loaded=$($og.l1_categories_loaded), want 30" }
        if ($og.l1_rules_total -ne 171) { throw "l1_rules_total=$($og.l1_rules_total), want 171" }
        Write-Host "[accept] /config: mode=shadow pv=pv2026.09.16 cats=30 rules=171" -ForegroundColor Green

        # curl.exe: PS 5.1 Invoke-WebRequest throws NullReferenceException (IE engine) on this box.
        # curl output arrives as a line array; join before -notmatch (array would filter, not negate).
        $metrics = (curl.exe -s "http://127.0.0.1:$pfPort/metrics") -join "`n"
        if ($metrics -notmatch 'otpmask_output_guard_mode\{[^}]*mode="shadow"') { throw 'metrics missing shadow mode gauge' }
        Write-Host '[accept] /metrics: output_guard shadow gauge present' -ForegroundColor Green

        $hz = Invoke-RestMethod "http://127.0.0.1:$pfPort/healthz" -TimeoutSec 10
        Write-Host "[accept] /healthz: $($hz | ConvertTo-Json -Compress)" -ForegroundColor Green
    } finally {
        if (-not $pf.HasExited) { Stop-Process -Id $pf.Id -Force -ErrorAction SilentlyContinue }
    }
    Write-Host "`n[OG-11] deployment accepted. Next: business smoke via Higress NodePort 31768 (OG-10 live chain)." -ForegroundColor Cyan
}

switch ($Stage) {
    'build' { Stage-Build }
    'upload' { Stage-Upload }
    'secret' { Stage-Secret }
    'rollout' { Stage-Rollout }
    'all' { Stage-Build; Stage-Upload; Stage-Secret; Stage-Rollout }
}
