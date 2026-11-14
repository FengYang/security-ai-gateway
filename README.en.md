> English ｜ [中文](./README.md)

# Confidential AI Gateway (security-ai-gateway)

**A unified multi-engine confidential-inference gateway.** Its core mission is **confidential inference**: built on **OTP-Mask vector encryption + the Higress Wasm plugin + TEE confidential inference**, it delivers an AI inference service where *the gateway link never touches plaintext*. Client text is encrypted before entering the TEE enclave; decryption, inference, sampling, and re-encryption all happen inside the trusted environment, with the entire link **fail-closed**. **The Higress plugin ecosystem is the core functional backbone** — the gateway's full feature surface (auth via key-auth/OAuth/OIDC, security via WAF/IP/Bot, rate limiting/canary/WasmPlugin hot-reload, multi-model proxying/MCP, etc.) is all carried by the Higress plugin system. **Security alone (an encryption tunnel) does not make an AI gateway** — security and the plugin feature surface together make a complete AI gateway.

## Positioning & Competitive Edge (Why Choose Us)

Enterprises want to put LLMs to work, yet hesitate to hand their data to the inference side — whether that is a public-cloud MaaS, a self-built GPU cluster, or the network and gateway in between. Any link that "sees plaintext" is a compliance and data-leakage red line. **The positioning of security-ai-gateway is to make the gateway link never touch plaintext**, reconciling the two usually conflicting goals of "using AI" and "protecting data."

### Core problems we solve
- **Plaintext exposure across the inference link**: traditional AI gateways can see the user prompt and model output right at the gateway, leaving data bare on the infrastructure side.
- **Security vs. functionality, choose one**: either a bare gateway (full features but no confidentiality), or sacrifice production feature surface such as rate limiting, auth, and observability for confidentiality.
- **Hardware TEE lock-in**: most confidential solutions tightly bind to specific hardware or clouds, raising the deployment bar and creating vendor lock-in.

### Gaps in existing solutions (our opportunity)
- Most "private AI gateways" on the market are **plaintext gateways + auth** — they do not provide link-level confidentiality, and the gateway still sees plaintext.
- Hardware TEE solutions typically **require specific confidential-computing instances**, making them hard to deploy on ordinary clusters.
- **General-purpose AI-gateway features are already a mature open-source foundation; end-to-end confidential trust remains scarce**: auth, rate limiting, WAF and multi-model proxying are carried by the Higress plugin ecosystem rather than reimplemented here. Based on a first-hand Oct 2026 review of public documentation and demos from major AI gateways (both open-source and commercial), we have not found a comparable open-source implementation covering the full chain of confidential plugins, key management / attestation and confidential inference. Comparable open-source projects (e.g. dstack `private-ai-gateway`) remain experimental (~30★). See the [full scoring matrix (§10)](https://github.com/FengYang/security-ai-gateway-docs/blob/main/GA-技术架构方案.md).

### Our differentiators
1. **Zero-plaintext link (end-to-end fail-closed)**: client text is encrypted before entering the TEE enclave; decryption, inference, sampling, and re-encryption all happen inside the trusted environment. The gateway and network only ever touch ciphertext, and any component failure **refuses service rather than degrading to plaintext**.
2. **Dual routes, no hardware binding**: Route 1 uses TEE confidential inference; Route 2 uses OTP-Mask vector encryption (per-element masking + PRG stream) to achieve confidential inference **without dedicated hardware TEEs** — one of this project's differentiating value propositions (Route 2 is under continuous evolution). The same paradigm already has commercial implementations, so this project does not claim to be first; our differentiation lies in enterprise-side gateway integration and open-source availability.
3. **Reuse Higress's production-grade AI-gateway plugin ecosystem**: auth (key-auth/OAuth/OIDC), security (WAF/Bot/IP), traffic (rate limiting/canary/WasmPlugin hot-reload), and AI-native capabilities (MCP/multi-model proxying) are all carried by the mature Higress plugin system rather than built from scratch — confidentiality without losing the production feature surface.
4. **Unified multi-engine governance**: TEE / OTP-Mask / C-MaaS engines are governed engine-agnostically across auth, Guardrail, audit, and multi-tenancy, so enterprises can switch backends per scenario without rewriting governance logic.
5. **Open source, self-hosted, enterprise-controllable**: Apache-2.0 licensed, self-hosted code, with no dependency on any vendor SaaS — enterprises own their confidential-inference capability.

### Comparison with the status quo

| Dimension | Traditional AI gateway (plaintext) | Hardware TEE solution | **security-ai-gateway** |
| --- | --- | --- | --- |
| Does the gateway see plaintext? | Yes | No (requires hardware) | **No (zero-plaintext link, may not require dedicated hardware)** |
| Hardware binding | None | Tightly bound to confidential-computing instances | Route 2 requires no dedicated hardware |
| Production feature surface (auth/rate-limit/WAF/MCP) | Yes | Implementation-dependent | **Reuses the full Higress plugin ecosystem** |
| Failure behavior | Implementation-dependent | Implementation-dependent | **End-to-end fail-closed (refuse, not degrade)** |
| Open source / self-hosted | Partial | Rare | **Apache-2.0, fully self-hosted** |

### Typical use cases
- **Strongly regulated industries** such as finance / healthcare / government, where prompts and outputs contain PII / sensitive data that must not leave the trusted domain.
- Using a **third-party / public-cloud MaaS** while requiring end-to-end confidential inference where the gateway cannot see plaintext.
- Obtaining **confidential-inference** capability **without purchasing confidential-computing hardware** (Route 2).
- Enterprises needing to **govern multiple inference backends uniformly** (self-built GPU-TEE / C-MaaS / external TEE).

## 1. Core Features

| Feature | Description |
| --- | --- |
| **Higress plugin ecosystem (core functional backbone)** | Production form is the Higress control plane (`deploy/higress/`), reusing the full plugin marketplace: key-auth/OAuth/OIDC (auth), WAF/Bot/IP Restriction (security), rate limiting/canary/WasmPlugin hot-reload (traffic), MCP/multi-model proxy (AI-native); the plugin chain ordering guarantees execution at segment ① before encryption, preserving ciphertext integrity |
| Confidential inference (Route A) | Plaintext exists only inside the TEE enclave; output returns as token ciphertext, decrypted by the gateway side into SSE |
| Unified southbound text payload (Route 1, D1) | Gateway → tee-infer encrypted throughout with K_enc (AES-256-GCM envelope, bidirectional sub-keys + anti-replay); vLLM OpenAI-compatible streaming / C-MaaS SDK channel |
| Unified multi-engine governance (Route 1) | `tee_gpu` (self-built GPU-TEE) / `cmaas` (Bailian confidential MaaS) / `external_tee` (reserved); auth/Guardrail/audit/multi-tenancy are engine-independent |
| OTP-Mask vector encryption (Route 2, reserved) | Per-element mod-R masking + HMAC-SHA256 PRG stream (rejection sampling, unbiased), R=2^32; vector payload path fully preserved for later advancement |
| Southbound private protocol | Varint binary wire format, HMAC signature + 30s anti-replay window + request_id deduplication; text payload/streaming fields appended (backward compatible) |
| Key lifecycle | Master key TTL 5min rotation + 30s in-flight window (forward secrecy); request key = HMAC(master, reqID\|model\|ts) |
| Multi-tenant isolation (M9) | Independent KeyManager per tenant; cross-tenant nonce rejection |
| Content-safety Guardrail (M9/M11) | In-TEE plaintext detection of PII/SQL injection/prompt injection (Unicode normalization + whitespace-obfuscation defense), hit → 403 fail-closed; **fills the content-safety gap left by C-MaaS** |
| Audit hash chain (M9) | 6.3 data model, SHA-256 chained tamper-evidence, verified via `/audit/verify`; C-MaaS attestation references recorded in audit (`cmaas_attest`) |
| Observability (M10) | Application `/metrics` (Prometheus text) + prebuilt Grafana dashboards |
| Deployment forms (M10) | Docker Compose (dev) / **Higress control plane (prod, `deploy/higress/`, D-0=B)** / K8s manifests + HPA/PDB / kind single-node (verification) |

## 2. Architecture & Data Flow

```
Client ──text──▶ Higress gateway (otpmask Wasm plugin)
                     │ 1. /key/issue (OTP key, via remote attestation)
                     │ 2. /embed (plaintext tokenization → vectors; trusted zone varies by scenario, see scenario matrix)
                     │ 3. vector + text OTP-Mask encryption → southbound protocol request (signed)
                     ▼
               tee-infer-service (TEE enclave)
                     │ verify signature → anti-replay → tenant key → decrypt (plaintext only here)
                     │ → Guardrail check → model inference/sampling → re-encrypt → sign response
                     ▼
              gateway plugin decrypts token → SSE streamed back to client
```

Components:

| Component | Tech | Port | Description |
| --- | --- | --- | --- |
| `gateway/wasm/otpmask-plugin` | Higress Wasm (Go 1.24 wasip1) | 10000 | Gateway plugin: key issuance, encryption, protocol construction, SSE assembly, JWT auth |
| `gateway/auth-service` | Go | 19200 | JWT issuance/verification (HS256, tenant auth, C-6) |
| `gateway/embedding-service` | Go + tiktoken (cl100k_base) | 18080 | Text → token → vector (plaintext; trusted zone varies by scenario, see scenario matrix) |
| `gateway/tee-infer-service` | Go (simulated TEE, MVP) | 19090 | Confidential inference, key management, guardrail, audit (in-memory/WORM), metrics; text payload SSE envelope stream |
| `gateway/vllm-adapter` | Go / Python | 19190 | vLLM plaintext inference bridge (Route 2 reserved; Route 1 connects tee-infer directly to vLLM OpenAI-compatible interface) |
| `gateway/attest-verify` | Go | 19191 | Attestation verification sidecar (D2): quote parsing + measurement baseline comparison, localhost `/verify` |
| `gateway/teecore` | Go library | - | KeyManager + non-linear operators (TEE trusted-side core) |
| `protocol/` | Go / Python / proto | - | Southbound protocol, three-end implementation (cross-consistency verified) |
| `cipher/mask`, `secagg/` | Go | - | OTP-Mask stream, secure aggregation (Paillier/Shamir) |

## 3. Quick Start (Docker Compose dev environment)

Prerequisites: Windows + winget (auto-installs missing pieces), or manually install Docker 19+, Go 1.24+, Python 3.10+.

```powershell
# Windows / macOS (PowerShell):
powershell -NoProfile -File scripts/setup-env.ps1
# Linux (production environment):
bash scripts/setup-env.sh          # tool install/build/compose; --skip-verify skips verification

# Or step by step (equivalent)
# 1. Build the wasm plugin (Go 1.24 native wasm)
$env:GOOS='wasip1'; $env:GOARCH='wasm'
go build -buildmode=c-shared -o gateway/wasm/otpmask-plugin/main.wasm ./gateway/wasm/otpmask-plugin

# 2. Start the environment (envoy + embedding + tee-infer + mock)
docker compose -f gateway/wasm/otpmask-plugin/docker-compose.yaml up -d --build

# 3. Gateway inference (via encrypted plugin link, SSE output)
curl -X POST http://127.0.0.1:10000/infer -H 'Content-Type: application/json' -H 'X-Tenant-ID: acme' -d '{"text":"hello secure ai"}'

# 4. Governance plane (usage/audit/metrics)
curl http://127.0.0.1:19090/usage
curl http://127.0.0.1:19090/audit/verify
curl http://127.0.0.1:19090/metrics

# 5. Full verification (23 items; Linux / macOS)
python3 scripts/verify-all.py
#    Windows also works: powershell -NoProfile -File scripts/verify-all.ps1 (forwards to the same implementation)
```

## 4. K8s Deployment (production path)

```bash
# Manifest validation (no cluster)
python3 scripts/verify-k8s.py

# Helm one-shot deployment (recommended; deploy/helm/otpmask)
helm install otpmask deploy/helm/otpmask \
  --set secret.sigKey=<real-value> --set secret.attestToken=<real-value>

# kustomize approach
kubectl apply -k deploy/k8s            # apply + HPA + PDB
kubectl apply -k deploy/monitoring     # Prometheus + Grafana

# Single-node real-machine verification (requires kind)
python3 scripts/verify-k8s.py --kind
```

See `docs/GA-部署指南.md` (Chinese): port mapping (gateway 10000 / Grafana 3000 / Prometheus 9090), secret injection, wasm image packaging, monitoring dashboards; interface docs in `docs/API-参考.md` (Chinese).

## 5. Security Model Summary

- **Trust boundary (by scenario, do not generalize)**: **Only in scenarios where the customer does not trust the infrastructure (confidential track S2/S3)** is plaintext narrowed to the TEE enclave (`tee-infer-service`) or to tee-infer inside the customer's trusted domain (S2) and the internal embedding service; the gateway and network link only touch ciphertext. **The plaintext path `/provider/*` (S1) belongs to the "customer's self-built trusted intranet" — plaintext stays within the customer's trusted domain and is not bound by the "plaintext must not leave the enclave" constraint.** Judgment basis and single source of truth: `docs/GA-产品场景与可信区域矩阵.md` §0.1 (Chinese).
- **Threat mitigation**: integrity (HMAC signature), anti-replay (30s window + deduplication), tenant isolation (independent KeyManager), content safety (Guardrail fail-closed), audit (hash chain), degradation policy (TEE unavailable → 503 refuse, never degrade to plaintext).
- **Auth boundary (known MVP item)**: `X-Tenant-ID` and the remote-attestation token are demo values; production must have the gateway issue auth (JWT) and inject it via TEE signature.
- Full threat model: `otp-mask-threat-model/`; audit conclusion: `docs/Phase3-M11-安全审计与渗透测试.md` (Chinese) (20/20 pentests passed, 1 P2 item fixed).

## 6. Directory Structure

```
cipher/          OTP-Mask mask stream, Paillier, KEX (cryptographic base)
secagg/          Secure aggregation (Shamir/aggregator/mTLS/audit)
gateway/
  wasm/          Higress plugins (otpmask main plugin + hello example)
  embedding-service/  Text-vector service
  tee-infer-service/  TEE confidential inference (incl. guardrail/audit/metrics)
  teecore/       KeyManager + non-linear operators
protocol/        Southbound protocol (Go/Python/proto, three-end consistent)
deploy/          K8s manifests + monitoring + kind config
scripts/         Verification suites (verify-all / verify-k8s / pen_test)
docs/            Milestone documents (M1-M12)
```

## 7. Documentation Index (currently valid; historical docs in `docs/archive/`)

**Entry point for new developers/integrators (read in order)**: `README.md` (Chinese) → `docs/GA-项目总览与路线图.md` (Chinese, full-progress roadmap; see "where we are" first) → `docs/GA-网关功能面研发计划.md` (Chinese, **current development basis**) → `docs/GA-路线1发布规划.md` (Chinese); role-based reading noted in each document's "Audience" field.

> Note: Most linked `docs/` documents are currently Chinese-only. English versions are being added for the repository's tracked entry documents; see each document's language switch at the top.

| Document | Content |
| --- | --- |
| `confidential-ai-gateway-whitepaper/` | **External-facing technical whitepaper** (HTML v3.0, macro + micro, multi-audience) |
| `docs/GA-项目总览与路线图.md` (Chinese) | **Single source of truth**: done/todo/preconditions/decision log/document map (updated after each step) |
| `docs/GA-网关功能面研发计划.md` (Chinese) | **Current main-line development plan (dev basis + pending review)**: gateway feature surface GF.1-GF.5 |
| `docs/GA-路线1发布规划.md` (Chinese) | Route 1 outline (P1-P5, accepted, historical main line) |
| `docs/GA-路线1研发落地验收报告.md` (Chinese) | Route 1 acceptance evidence (M1-M3 frozen) and leftover items (M4) |
| `docs/GA-AI网关能力补齐方案.md` (Chinese) | Gateway feature-surface plan (v4, in progress) |
| `docs/supply-chain/GA-供应链与出境登记.md` (Chinese) | B6 main body: provider entity + domestic/export checks, model license/revision/quantization/engine registration and offline rebuild |
| `ai-gateway-roadmap/ai-gateway-roadmap.html` | **Strategic roadmap (management view)**: three-phase strategy/timeline/acceptance/resources; progress single-source in `docs/GA-项目总览与路线图.md` |
| `docs/GA-CMAAS对接设计.md` (Chinese) | C-MaaS engine integration design |
| `docs/总体技术方案-v2.md` (Chinese) | Architecture baseline v3.0 (incl. §2.4/§3.10 gateway feature surface) |
| `docs/API-参考.md` (Chinese) | Full service interface contracts (text payload/SSE envelope/quota endpoints) |
| `docs/GA-部署指南.md` (Chinese) | Deployment paths (incl. Higress control-plane form) + ops/incident response |
| `docs/GA-计费接口设计.md` (Chinese) | External billing integration (token metering/reconciliation) |
| `docs/GA-TDX移植设计.md`, `docs/GA-第三方审计材料包.md` (Chinese) | M4 real-machine prereq / external-audit material prep |
| `docs/路线2研究跟踪.md` (Chinese) | Route 2 long-term research tracking list |
| `docs/output-guard/` | **Output-side content review (OG) domain (16 docs)**: main body = `GA-输出侧内容审查-技术实现方案.md` (sole source of truth); sub-volumes = dev plan, ledger, evidence (review/handling/report/SOP); system & dependencies in `docs/GA-项目总览与路线图.md` §9.2 |
| `docs/详细设计/` | **Procedural detailed-design library (gateway capability build-out, 37 docs)**: master/sub = `GA-AI网关能力补齐--研发计划与进度跟踪.md` (top level); module main bodies = 5 under `P0/` (multi-model routing / semantic cache / token billing / national-crypto S2 / TEE security trio, all sole sources of truth); evidence = 31 review reports; positioning & conventions in `docs/GA-项目总览与路线图.md` §9 "Directory Conventions" and §9.5 |
| `docs/archive/` | **Historical document archive (32 docs, audit trail, not current basis)**, index in `docs/archive/README.md` |
| `otp-mask-threat-model/` | Threat model (TH-01~13 + GW-01~10) |

## 8. Status

Phase 1-3 (M1-M12) all complete ✅ → **Route 1 (unified multi-engine confidential-inference gateway) M1-M3 achieved, code frozen**; gateway feature-surface core set (quota/desensitization/decoration/double-hash + Envoy base) complete; D-0 corrected to Higress control-plane form, `deploy/higress/` manifests ready pending cluster deployment. **Next: advance GF.1 (Higress control-plane landing) per `docs/GA-网关功能面研发计划.md`**; remaining work is blocked on external dependencies (M4 real machine: TDX hardware / C-MaaS account) or scheduled per the dev plan. Full progress in `docs/GA-项目总览与路线图.md` (Chinese).

## 9. Contributing & License

Licensed under [Apache License 2.0](./LICENSE). Before contributing, please read [CLA.md](./CLA.md); a `Signed-off-by` line in your commit constitutes acceptance. Third-party attributions are listed in [NOTICE](./NOTICE).
