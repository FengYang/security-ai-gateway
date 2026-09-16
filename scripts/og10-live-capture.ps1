# og10-live-capture.ps1 - OG-10 live capture: real Higress SSE chain on LAN K3s.
#
# Flow: port-forward gateway pod (containerPort 30000) -> warmup (fail-closed 503
# convergence) -> capture real /v1/infer SSE dump -> metrics side-evidence ->
# run gated framewise test (OG10_LIVE_DUMP) -> report + exit code.
#
# NOTE: keep this script ASCII-only (PS 5.1 reads BOM-less files as ANSI).
# The default prompt contains Chinese -> ship as UTF-8 with BOM.

param(
    [int]$Port = 31770,          # local port for gateway tunnel (pod 30000)
    [int]$MetricsPort = 19091,   # local port for tee-infer metrics side-evidence
    [string]$Prompt = 'Write one short sentence about spring rain.',
    [string]$DumpDir = ''        # defaults to <repo>\.tools\og10-live
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$env:KUBECONFIG = Join-Path $root '.tools\k3s-kubeconfig.yaml'
if (-not (Test-Path $env:KUBECONFIG)) { Write-Host "FATAL: kubeconfig not found: $env:KUBECONFIG"; exit 2 }
$env:KUBECACHEDIR = Join-Path $env:TEMP 'k8s-cache-og'

if (-not $DumpDir) { $DumpDir = Join-Path $root '.tools\og10-live' }
New-Item -ItemType Directory -Force -Path $DumpDir | Out-Null
$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$dumpFile = Join-Path $DumpDir "dump-$ts.sse"
$reqFile  = Join-Path $DumpDir "req-$ts.json"

function Get-RunningGatewayPod {
    $pods = kubectl get pods -n higress-system -o json | ConvertFrom-Json
    $gw = $pods.items | Where-Object { $_.metadata.name -like 'higress-gateway-*' -and $_.status.phase -eq 'Running' } | Select-Object -First 1
    if (-not $gw) { throw 'no Running higress-gateway pod found' }
    return $gw.metadata.name
}

function Invoke-Sse {
    # POST one SSE request; returns @{ code; body-file }.
    param([string]$Url, [string]$ApiKey, [string]$BodyFile, [string]$OutFile)
    $code = & curl.exe -sS --max-time 60 -X POST `
        -H 'Accept: text/event-stream' `
        -H "x-api-key: $ApiKey" `
        -H 'Content-Type: application/json' `
        --data-binary "@$BodyFile" `
        -o $OutFile `
        -w '%{http_code}' $Url 2>$null
    return @{ code = "$code"; body = $OutFile }
}

# --- 1. targets ------------------------------------------------------------
$gwPod = Get-RunningGatewayPod
Write-Host "[1] gateway pod: $gwPod (tunnel 127.0.0.1:$Port -> pod:30000)"

$ka = kubectl get wasmplugin key-auth -n higress-system -o json | ConvertFrom-Json
$apiKey = $ka.spec.defaultConfig.consumers[0].credential
if (-not $apiKey) { throw 'cannot read key-auth credential from cluster' }
Write-Host "[1] key-auth credential read from cluster (len=$($apiKey.Length))"

# --- 2. request body (BOM-less UTF-8; curl --data-binary passes bytes as-is) --
# engine_type=cmaas routes to real C-MaaS text SSE (finishTextDirect); without
# engine_type the plugin falls back to the legacy embedding->vectors path.
$reqObj = @{ messages = @(@{ role = 'user'; content = $Prompt }); stream = $true; engine_type = 'cmaas' }
[IO.File]::WriteAllText($reqFile, (ConvertTo-Json $reqObj -Depth 5 -Compress))

# --- 3. tunnels -------------------------------------------------------------
$pfArgs = @('-n', 'higress-system', 'port-forward', "pod/$gwPod", "$($Port):30000")
$pf = Start-Process -FilePath 'kubectl' -ArgumentList $pfArgs -PassThru -WindowStyle Hidden
$mfArgs = @('-n', 'otpmask', 'port-forward', 'svc/tee-infer-service', "$($MetricsPort):19090")
$mf = Start-Process -FilePath 'kubectl' -ArgumentList $mfArgs -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 4

function Get-GuardMetric {
    $m = curl.exe -sS --max-time 5 "http://127.0.0.1:$MetricsPort/metrics" 2>$null | Select-String 'otpmask_output_guard_requests_total'
    if (-not $m) { return '' }
    return ($m -join ' | ')
}

try {
    # --- 4. warmup: fail-closed 503 convergence (session-storm retry) -------
    $url = "http://127.0.0.1:$Port/v1/infer"
    $warmFile = Join-Path $DumpDir "warmup-$ts.out"
    $code = '000'
    for ($i = 1; $i -le 5; $i++) {
        $r = Invoke-Sse -Url $url -ApiKey $apiKey -BodyFile $reqFile -OutFile $warmFile
        $code = $r.code
        Write-Host "[4] warmup attempt $i -> HTTP $code"
        if ($code -eq '200') { break }
        Start-Sleep -Seconds 2
    }
    if ($code -ne '200') { throw "warmup failed after retries (last HTTP $code); check gateway tunnel/ingress/key-auth" }

    # --- 5. metrics before -> capture live SSE dump -> metrics after --------
    $metricBefore = Get-GuardMetric
    $cap = Invoke-Sse -Url $url -ApiKey $apiKey -BodyFile $reqFile -OutFile $dumpFile
    if ($cap.code -ne '200') { throw "capture failed: HTTP $($cap.code)" }
    $dumpRaw = [IO.File]::ReadAllText($dumpFile)
    if (-not $dumpRaw.Contains('[DONE]')) { throw 'captured stream missing [DONE] (truncated)' }
    if (-not $dumpRaw.Contains('finish_reason')) { throw 'captured stream missing finish_reason (not OpenAI SSE?)' }
    $nFrames = ($dumpRaw -split "`n" | Where-Object { $_.StartsWith('data:') }).Count
    $metricAfter = Get-GuardMetric
    Write-Host "[5] captured $nFrames SSE data lines -> $dumpFile"
    Write-Host "[5] metrics before: $metricBefore"
    Write-Host "[5] metrics after : $metricAfter"

    # --- 6. gated framewise test (assertions live in repo test file) --------
    Write-Host '[6] running gated framewise test (OG10_LIVE_DUMP)...'
    $env:OG10_LIVE_DUMP = $dumpFile
    Push-Location (Join-Path $root 'gateway\tee-infer-service')
    $testOk = $false
    try {
        go test -mod=mod . -run TestOutputGuardFramewiseLiveHigress -count=1 -v
        $testOk = ($LASTEXITCODE -eq 0)
    } finally {
        Pop-Location
        Remove-Item Env:\OG10_LIVE_DUMP -ErrorAction SilentlyContinue
    }
    if (-not $testOk) { throw 'gated framewise test FAILED (see go test output above)' }

    Write-Host ''
    Write-Host "OG-10 LIVE CAPTURE PASS: frames=$nFrames dump=$dumpFile"
    exit 0
} catch {
    Write-Host "OG-10 LIVE CAPTURE FAIL: $($_.Exception.Message)"
    exit 1
} finally {
    foreach ($p in @($pf, $mf)) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
}
