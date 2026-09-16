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
#   16. GA OG-10 framewise e2e  SSE per-frame capture + "hit fragment never in any delivered frame"
#                                (shadow negative check + enforcing shape contract: per-frame & cross-frame)
#
# Usage: powershell -NoProfile -File scripts/verify-all.ps1

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$go = $env:GO_BIN
if (-not $go) {
    $g = Get-Command go -ErrorAction SilentlyContinue
    if ($g) { $go = $g.Source } else { $go = 'C:\Program Files\Go\bin\go.exe' }
}
$results = @()

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
data = json.dumps({'text': 'e2e check'}).encode()
req = urllib.request.Request('http://127.0.0.1:10000/infer', data=data, headers={'Content-Type': 'application/json'})
body = urllib.request.urlopen(req, timeout=20).read().decode()
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
$metricsOut = python -c "import urllib.request; b=urllib.request.urlopen('http://127.0.0.1:19090/metrics', timeout=5).read().decode(); print('otpmask_inference_requests_total' in b and 'otpmask_audit_events' in b)" 2>&1 | Out-String
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
$pyCheck = python -c "import ast; ast.parse(open('gateway/vllm-adapter/vllm_adapter.py', encoding='utf-8').read()); print('ok')" 2>&1 | Out-String
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

# 16. vLLM 密态改造（masked 包单测 + 补算新算子 + 语法）
Write-Host "`n[16/16] vLLM 密态改造（masked 包 + 补算 rmsnorm/argmax）" -ForegroundColor Yellow
& $go test ./gateway/teecore/ -run 'TestRMSNorm' *> $null
$rmsOk = $LASTEXITCODE -eq 0
& $go test ./gateway/tee-infer-service/ -run 'TestRecomputeRMSNormArgMax' *> $null
$recompOpsOk = $LASTEXITCODE -eq 0
$pyExe = Get-Command python -ErrorAction SilentlyContinue
if ($pyExe) {
    $maskedTest = Join-Path $root 'vllm\vllm\masked\test_masked_core.py'
    if (Test-Path $maskedTest) {
        & python $maskedTest *> $null
        $maskedOk = $LASTEXITCODE -eq 0
    } else { $maskedOk = $true }  # 未放置 vllm 源码时跳过
} else { $maskedOk = $true }
Check 'vLLM masked dev (RMSNorm + recompute ops + core tests)' ($rmsOk -and $recompOpsOk -and $maskedOk) '(P1-P4 hooks ready; GPU env required for e2e)'

# 17. 路线 1：text 载荷全链路（P2/P5，D1 南向统一 text）
Write-Host "`n[17/18] 路线 1 text 载荷全链路（tee_gpu 流式 + cmaas fail-closed + guardrail）" -ForegroundColor Yellow
& $go test ./gateway/tee-infer-service/ -run 'TestTextInfer' *> $null
$textInfer = $LASTEXITCODE -eq 0
& $go test ./gateway/tee-infer-service/model/ -run 'TestRemoteEngineGenerate|TestCmaasEngine|TestLocalEngineGenerate' *> $null
$engStream = $LASTEXITCODE -eq 0
Check '路线 1 text 全链路 (text 载荷 + SSE 信封 + 引擎流式)' ($textInfer -and $engStream) '(quote 会话 + tee_gpu/cmaas + guardrail 拦截 + 引擎流式 fail-closed)'

# 18. 路线 1：降级攻击/重放/乱序 + 协议一致性（P1a/P1b 升级 + P2 text 载荷字段）
Write-Host "`n[18/18] 路线 1 防降级/反重放/流序 + 跨语言一致性" -ForegroundColor Yellow
& $go test ./gateway/tee-infer-service/ -run 'TestSessionEnvelopeReplay|TestSessionPlaintextFailClosed|TestSessionKeyIsolation|TestSessionDestroyAndZeroize' *> $null
$envReplay = $LASTEXITCODE -eq 0
& $go test ./gateway/attest-verify/... *> $null
$sidecarOk = $LASTEXITCODE -eq 0
python protocol/python/cross_test.py *> $null
$crossOk = $LASTEXITCODE -eq 0
Check '路线 1 反重放/防降级 + sidecar + 跨语言一致性' ($envReplay -and $sidecarOk -and $crossOk) '(信封重放拒绝 + 明文 fail-closed + attest-verify sidecar + Go/Py text 载荷一致)'

# 19. AI 网关能力补齐（P0a/P1/P2a）：配额管控 + 脱敏/装饰 + 双 hash 审计
Write-Host "`n[19/19] AI 网关能力补齐（配额 + 脱敏 + 装饰 + 双 hash）" -ForegroundColor Yellow
& $go test ./gateway/tee-infer-service/ -run 'TestQuota|TestMaskPII|TestPII|TestInjectionAlways|TestSystemPrompt' *> $null
$capOk = $LASTEXITCODE -eq 0
Check 'AI 网关能力补齐（P0a/P1/P2a）' $capOk '(token 配额 429/预占防超卖 + PII 脱敏/拦截 + 提示词装饰 + transformed_hash 审计)'

# 20. Higress 插件版本门禁（防"版本漂移 → wasm 404 → 静默放行"）
Write-Host "`n[20] Higress 插件版本门禁（仓库 ↔ 锁定 ↔ 镜像）" -ForegroundColor Yellow
& powershell -NoProfile -File scripts/check-higress-plugin-versions.ps1 -Container higress-chain-control-plane *> $null
Check 'Higress plugin versions' ($LASTEXITCODE -eq 0) '(deploy 清单 ↔ plugin-versions.lock ↔ 运行镜像；版本错配即 FAIL)'

# 21. 指标"全绿"可执行判定（门禁 #9：required 全命中 + 三来源必须全可达）
Write-Host "`n[21] 指标全绿判定（门禁 #9）" -ForegroundColor Yellow
& powershell -NoProfile -File scripts/check-metrics-green.ps1 -RequireAllSources -CoreToken $env:OTP_CORE_AUTH_TOKEN *> $null
Check 'Metrics all-green (gate #9)' ($LASTEXITCODE -eq 0) '(scripts/metrics-required.txt：required 缺席即 FAIL；来源不可达在门禁模式亦 FAIL)'

# 22. 审计-计量对账（S5 判据 6）：窗口 0 容差 + 差异分类 + 出账阻断与恢复
Write-Host "`n[22] 审计-计量对账（S5 / 门禁 #7 判据 6）" -ForegroundColor Yellow
& $go test ./gateway/tee-infer-service/ -run 'TestReconcile' *> $null
Check 'Metering reconcile (gate #7 / S5)' ($LASTEXITCODE -eq 0) '(窗口 0 容差 + 分类 chain_broken/usage_reset/multi_instance/audit_behind + 出账阻断与恢复解阻断；实链只读核对见 scripts/verify-metering-reconcile.ps1)'

# 23. GA-输出侧内容审查 OG-10：逐帧 e2e 断言工具（SSE 抓包）
#     -mod=mod：本仓库 vendor/modules.txt 与 go.mod 不一致（与本文件其余 go test 项的差异见记忆台账）
Write-Host "`n[23] 输出侧逐帧 e2e 断言（OG-10：命中片段在任何已下发帧零出现）" -ForegroundColor Yellow
& $go test -mod=mod ./gateway/tee-infer-service/ -run 'TestFramewise|TestOutputGuardFramewise' -count=1 *> $null
Check 'Output-guard framewise e2e (OG-10)' ($LASTEXITCODE -eq 0) '(shadow 负向验证：工具能检出已下发命中；enforcing 形态：逐帧+跨帧零命中 + content_filter 终止码)'

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
