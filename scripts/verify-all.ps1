# verify-all.ps1 - M1-M12 + C-class automated verification suite (G3 + Phase3 M9-M12)
#
# Runs all verification items sequentially and summarizes PASS/FAIL.
# Exit code: 0 = all passed, 1 = at least one failure.
#
# Coverage:
#   1. Unit tests      go test ./...
#   2. Protocol cross  Python<->Go southbound protocol consistency (incl. cipher_text)
#   3. Decision gate   fixed-r + W*r mask-image math PoC
#   4. Runtime env     Docker containers (envoy/embedding/tee-infer)
#   5. E2E             text -> encrypt -> TEE infer -> decrypt -> SSE
#   6. Precision       ciphertext inference == plaintext inference (0% loss)
#   7. M9 governance   multi-tenant isolation / usage metering / audit chain / guardrail
#   8. M10 deploy      K8s manifests (kustomize/YAML/images) + app /metrics endpoint
#   9. M11 security    dynamic penetration tests (tamper/replay/cross-tenant/guardrail bypass/DoS/fail-closed)
#   10. M12 vLLM       engine abstraction (RemoteEngine == local), adapter build, python adapter syntax
#   11. vLLM+auth+canary  build/tests/dry-run
#   12. Enclave   enclave.go (Attest/Seal/Unseal/Measure + seal-file roundtrip)
#   13. Attestation  challenge-response + session key agreement + verify chain rejection
#   14. R2 masked-infer  cipher kernel parity + /v1/recompute + dual-route routing
#   15. A6 + TSA + reconcile  no-plaintext observability + RFC3161 TST + audit-metering reconcile
#
# Usage: powershell -NoProfile -File scripts/verify-all.ps1

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

Write-Host "===== M1-M12 automated verification =====" -ForegroundColor Cyan
Push-Location $root

# 1. Unit tests
Write-Host "`n[1/7] Unit tests (go test ./...)" -ForegroundColor Yellow
& $go test ./... *> $null
Check 'Unit tests' ($LASTEXITCODE -eq 0) '(all packages)'

# 2. Protocol cross
Write-Host "`n[2/7] Protocol cross (Go/Python, incl. cipher_text)" -ForegroundColor Yellow
python protocol/python/cross_test.py *> $null
Check 'Protocol cross' ($LASTEXITCODE -eq 0)

# 3. Decision gate PoC
Write-Host "`n[3/7] Decision gate PoC (mask-image math)" -ForegroundColor Yellow
$pocOut = & $go run ./gateway/poc/linear-mask-poc 2>&1 | Out-String
Check 'Decision gate PoC' ($pocOut -match 'PASS')

# 4. Runtime env
Write-Host "`n[4/7] Runtime env (Docker containers)" -ForegroundColor Yellow
$needContainers = @('otpmask-plugin-envoy-1', 'otpmask-plugin-embedding-service-1', 'otpmask-plugin-tee-infer-service-1')
$up = (docker ps --filter 'status=running' --format '{{.Names}}') -split "`r?`n"
$envOk = $true
foreach ($c in $needContainers) {
    if ($up -notcontains $c) { $envOk = $false }
}
Check 'Docker containers ready' $envOk

# 5. E2E (text -> SSE)
Write-Host "`n[5/7] E2E (text -> encrypt -> TEE infer -> decrypt -> SSE)" -ForegroundColor Yellow
$e2eScript = @"
import urllib.request, json
data = json.dumps({'text': 'e2e check'}).encode
req = urllib.request.Request('http://127.0.0.1:10000/infer', data=data, headers={'Content-Type': 'application/json'})
body = urllib.request.urlopen(req, timeout=20).read.decode
print(body)
assert 'data: [DONE]' in body, 'missing SSE done marker'
assert 'data: {' in body, 'missing SSE token line'
"@
$e2eOut = python -c $e2eScript 2>&1 | Out-String
Check 'E2E SSE flow' ($LASTEXITCODE -eq 0) (($e2eOut -replace "`n", ' ').Trim)

# 6. Precision
Write-Host "`n[6/7] Precision (cipher == plain)" -ForegroundColor Yellow
$precOut = & $go run ./gateway/tee-infer-service/e2e/precision 2>&1 | Out-String
Check 'Precision parity' ($precOut -match 'PASS')

# 7. M9 governance (multi-tenant / usage / audit / guardrail) + C-4/C-5 (version consistency / WORM audit)
Write-Host "`n[7/12] M9 governance + C-4/C-5 (version / WORM audit)" -ForegroundColor Yellow
& $go test ./gateway/tee-infer-service/ -run 'TestM9|TestGuardrail|TestProtocolVersion|TestAuditWORM' *> $null
Check 'M9 + C4/C5 tests' ($LASTEXITCODE -eq 0) '(governance / version consistency / WORM persist)'

# 8. M10 K8s manifests + app metrics endpoint
Write-Host "`n[8/12] M10 K8s manifests (kustomize + YAML + images)" -ForegroundColor Yellow
$m10Out = & cmd /c "powershell -NoProfile -File scripts\verify-k8s.ps1 2>&1" | Out-String
Check 'M10 K8s manifests' ($LASTEXITCODE -eq 0) (($m10Out -replace "`n", ' ').Trim)
Write-Host "`n[9/12] App /metrics endpoint" -ForegroundColor Yellow
$metricsOut = python -c "import urllib.request; b=urllib.request.urlopen('http://127.0.0.1:19090/metrics', timeout=5).read.decode; print('otpmask_inference_requests_total' in b and 'otpmask_audit_events' in b)" 2>&1 | Out-String
Check 'App /metrics endpoint' ($metricsOut -match 'True') '(tee-infer exposes Prometheus text)'

# 10. M11 penetration tests
Write-Host "`n[10/12] M11 penetration tests (20 checks)" -ForegroundColor Yellow
$penOut = python scripts/pen_test.py 2>&1 | Out-String
Check 'M11 penetration' ($LASTEXITCODE -eq 0) ((($penOut -split "`r?`n" | Select-Object -Last 3) -join ' ').Trim)

# 11. vLLM adapter (M12) + auth-service (C-6) + canary script (C-7)
Write-Host "`n[11/15] vLLM + auth-service + canary tooling" -ForegroundColor Yellow
& $go build ./gateway/vllm-adapter/ *> $null
$vllmBuild = $LASTEXITCODE -eq 0
& $go test ./gateway/tee-infer-service/model/ *> $null
$vllmTest = $LASTEXITCODE -eq 0
$pyCheck = python -c "import ast; ast.parse(open('gateway/vllm-adapter/vllm_adapter.py', encoding='utf-8').read); print('ok')" 2>&1 | Out-String
$vllmPy = $pyCheck -match 'ok'
& $go build ./gateway/auth-service/ *> $null
$authBuild = $LASTEXITCODE -eq 0
& $go test ./gateway/auth-service/ *> $null
$authTest = $LASTEXITCODE -eq 0
& powershell -NoProfile -File scripts/canary-release.ps1 -Action deploy -Tag v-dryrun -DryRun *> $null
$canaryOk = $LASTEXITCODE -eq 0
Check 'vLLM + auth + canary (build/tests/dry-run)' ($vllmBuild -and $vllmTest -and $vllmPy -and $authBuild -and $authTest -and $canaryOk) '(RemoteEngine==local + JWT 5 + canary dry-run)'

# 12. Enclave 抽象（Attest/Seal/Unseal/Measure + 密封文件往返）
Write-Host "`n[12/15] Enclave abstraction (enclave.go)" -ForegroundColor Yellow
& $go test ./gateway/tee-infer-service/ -run 'TestMockEnclave|TestSealFileRoundtrip|TestNewPlatformEnclave' *> $null
Check 'Enclave abstraction' ($LASTEXITCODE -eq 0) '(seal/unseal roundtrip + measure stable + platform stub)'

# 13. 远程证明链（挑战-响应 + 会话密钥派生 + 验证链拒绝路径）
Write-Host "`n[13/15] Remote attestation (challenge-response + session keys)" -ForegroundColor Yellow
& $go test ./gateway/tee-infer-service/ -run 'TestSession|TestVerifyAttestation|TestRemoteAttestationE2E' *> $null
Check 'Remote attestation chain' ($LASTEXITCODE -eq 0) '(A1 proof chain + A2 ECDH/HKDF agreement + tamper rejection)'

# 14. 路线 2（密文线性内核 + 补算服务 + 双路线路由）
Write-Host "`n[14/15] R2 密文线性内核 + 补算 + 双路线路由" -ForegroundColor Yellow
& $go test ./gateway/teecore/maskedinfer/ -run 'TestCipherLinearParity|TestB2|TestB3|TestQuantize' *> $null
$r2kernel = $LASTEXITCODE -eq 0
& $go test ./gateway/tee-infer-service/ -run 'TestRecomputeE2E|TestDualRoute|TestRoute' *> $null
$r2recomp = $LASTEXITCODE -eq 0
Check 'R2 masked-infer (kernel parity + recompute + routing)' ($r2kernel -and $r2recomp) '(B1/B2/B3/B4/B5 + dual-route e2e)'

# 15. A6 明文最小化 + 基座（TSA/对账/探针）+ 全套回归
Write-Host "`n[15/15] A6 明文最小化 + 基座增强 + 全套回归" -ForegroundColor Yellow
& $go test ./gateway/tee-infer-service/ -run 'TestA6|TestMockTSA|TestAuditAnchorTST|TestReconciler' *> $null
$baseOk = $LASTEXITCODE -eq 0
& $go test ./... *> $null
$allOk = $LASTEXITCODE -eq 0
Check 'A6 + TSA + reconcile + full regression' ($baseOk -and $allOk) '(no-plaintext + RFC3161 TST + audit-metering reconcile)'

Pop-Location

# Summary
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
