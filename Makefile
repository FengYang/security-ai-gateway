# OTP-Mask 工业级实现 — 工程入口
# 目标：lint → vet → test(-race) → bench → coverage 全链路

GO ?= go

.PHONY: all
all: vet lint test

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: test
test:
	$(GO) test -race -count=1 ./...

.PHONY: test-short
test-short:
	$(GO) test -race -short ./...

# test-e2e —— §11.4/11.5 进程级集成/端到端回归（INT-1..5 + E2E-01..04/06；
# 真实二进制子进程 + 仅 HTTP 驱动；E2E-05 完整切换演练留部署环境，见 make drill）。
.PHONY: test-e2e
test-e2e:
	$(GO) test -tags e2e -count=1 -v -timeout 15m ./e2e/

.PHONY: fuzz
fuzz:
	$(GO) test -fuzz=FuzzDecrypt -fuzztime=30s ./cipher/paillier/
	$(GO) test -fuzz=FuzzReconstruct -fuzztime=30s ./secagg/shares/
	$(GO) test -fuzz=FuzzReceiveBundles -fuzztime=30s ./secagg/
	$(GO) test -fuzz=FuzzUnmaskPartDecode -fuzztime=30s ./secagg/
	$(GO) test -fuzz=FuzzFinalizeMalformedShares -fuzztime=30s ./secagg/

.PHONY: fuzz-quick
fuzz-quick:
	$(GO) test -fuzz=FuzzReceiveBundles -fuzztime=10s ./secagg/
	$(GO) test -fuzz=FuzzUnmaskPartDecode -fuzztime=10s ./secagg/
	$(GO) test -fuzz=FuzzFinalizeMalformedShares -fuzztime=10s ./secagg/

.PHONY: bench
bench:
	$(GO) test -bench=. -benchmem -run=^$$ ./cipher/paillier/ ./secagg/shares/

# bench-s2 —— §8.3 国密 S2 基准（T-8.1 微基准 + T-8.2/T-8.3 硬断言）。
# 分两段：
#   1. 微基准（Benchmark*，不计 pass/fail，仅输出性能数据）
#   2. 硬断言（T-8.2 P99 延迟、T-8.3 batch vs sequential 加速比，不通过即失败）
.PHONY: bench-s2
bench-s2:
	@echo "===== [1/2] S2 微基准 ====="
	$(GO) test -bench=. -benchmem -run=^$$ ./gateway/cryptop/ ./gateway/cryptopsvc/
	@echo "===== [2/2] S2 硬断言（T-8.2 / T-8.3） ====="
	$(GO) test -run="TestSidecarSealLatencyP99|TestBatchVsSequential" -count=1 -v ./gateway/cryptopsvc/

.PHONY: coverage
coverage:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out

.PHONY: audit
audit:
	govulncheck ./...

.PHONY: tidy
tidy:
	$(GO) mod tidy

# wasm-guard —— §9.1「Wasm 内无密码运算」门禁（R-11/P3）。
#   v1.9 修订（评审发现）：原「deps 图 ^crypto/ 零输出」**不可满足**——插件经 higress wrapper
#   链入 net/http，而 net/http→crypto/tls→crypto/*（任意 crypto/ 包恒出现）。故按 R-11 口径
#   「禁止**直接**密码 import」+ §9.1「源码 import 块扫描」，改为三条机械可验证断言：
#     ①a 插件**源码**（含子包，非 _test.go）direct import 零密码；
#     ①b 依赖闭包内**本仓** security-ai-gateway/* 包的 direct import 零密码，且闭包不含 gmsm
#         （捕获「插件经自研包间接链入密码」；本仓包可精确定位，不受 net/http 噪声影响）；
#     ②  framing 包 protocol/go 自身零密码不变量。
#   任一违例 → 打印清单并非 0 退出。go list 的 Imports 字段不含 _test.go 依赖，天然排除测试。
#   ⚠️ go 命令显式 `-mod=mod`（2026-10-19 加固）：仓库根存在未追踪 vendor/ 时，裸 `go list`
#   会以 inconsistent vendoring 失败且 stdout 为空 ⇒ `$$(...)` 捕获空串 ⇒ 门禁**空跑假绿**
#   （T-4 复现实测 NOFLAG_EXIT=1 OUTLEN=0）；显式 -mod=mod 消除该静默失效路径（与 CI 既有口径一致）。
# 插件包清单（wasm-guard 断言①覆盖范围）：**新增插件必须加入本清单**（T-4 起含 mcp-acl）。
WASM_PLUGIN_PKGS ?= ./gateway/wasm/otpmask-plugin/... ./gateway/wasm/mcp-acl-plugin/...

.PHONY: wasm-guard
wasm-guard:
	@echo "== wasm-guard 断言①a：插件源码 direct import 零密码（R-11/§9.1）=="
	@out=$$($(GO) list -mod=mod -f '{{range .Imports}}{{.}}{{"\n"}}{{end}}' $(WASM_PLUGIN_PKGS) | grep -E '^(crypto/|github.com/emmansun/gmsm|security-ai-gateway/cipher/mask|security-ai-gateway/protocol/go/cryptoops)' | sort -u || true); \
	if [ -n "$$out" ]; then echo "FAIL: 插件源码直接 import 密码包——"; echo "$$out"; exit 1; fi; \
	echo "PASS: 插件源码零密码 import"
	@echo "== wasm-guard 断言①b：闭包内本仓包与 gmsm 无密码 =="
	@badmod=$$($(GO) list -mod=mod -deps -f '{{.ImportPath}}' $(WASM_PLUGIN_PKGS) | grep -E '^github.com/emmansun/gmsm' || true); \
	if [ -n "$$badmod" ]; then echo "FAIL: 插件链入 gmsm——"; echo "$$badmod"; exit 1; fi; \
	bad=$$($(GO) list -mod=mod -deps -f '{{.ImportPath}} {{range .Imports}}{{.}} {{end}}' $(WASM_PLUGIN_PKGS) | grep -E '^security-ai-gateway/' | grep -E ' (crypto/[a-z0-9/]+|github\.com/emmansun/gmsm|security-ai-gateway/cipher/mask|security-ai-gateway/protocol/go/cryptoops)( |$$)' || true); \
	if [ -n "$$bad" ]; then echo "FAIL: 闭包内本仓包链入密码求值包——"; echo "$$bad"; exit 1; fi; \
	echo "PASS: 闭包内本仓包零密码"
	@echo "== wasm-guard 断言②：protocol/go framing 包零密码不变量 =="
	@out=$$($(GO) list -mod=mod -deps -f '{{.ImportPath}}' security-ai-gateway/protocol/go | grep -E '(^crypto/(aes|cipher|hmac|sha256|sha512|ecdh|ecdsa)|gmsm)' || true); \
	if [ -n "$$out" ]; then echo "FAIL: protocol/go 链入密码包——"; echo "$$out"; exit 1; fi; \
	echo "PASS: protocol/go 零密码"

# wasm-artifact-guard —— wasm 产物**真身**断言（T-4 集群窗口缺口：假绿第二形态）。
#   机制：`GOOS=wasip1 GOARCH=wasm` 在「WSL 调 Windows go.exe」下**不传递环境变量**
#   （实测 `GOOS=wasip1 GOARCH=wasm go.exe env GOOS GOARCH` → `windows amd64`）⇒ 产物实为
#   Windows PE(DLL)（magic `4D 5A`），Envoy 判 `fetched Wasm binary ... is invalid`；而旧流程
#   **只看退出码** ⇒ 静默假绿（首轮上集群的 9,522,460 B 产物即此）。
#   本目标对产物做 magic 断言（wasm = `\0asm` = 0061736d）；仅校验**已存在**的产物
#   （缺产物 SKIP，便于单目标构建），全部缺失则失败（防门禁空跑）。
WASM_ARTIFACTS ?= gateway/wasm/otpmask-plugin/main.wasm gateway/wasm/mcp-acl-plugin/main.wasm

.PHONY: wasm-artifact-guard
wasm-artifact-guard:
	@n=0; \
	for f in $(WASM_ARTIFACTS); do \
	  if [ ! -f "$$f" ]; then echo "SKIP: $$f（无产物）"; continue; fi; \
	  magic=$$(head -c 4 "$$f" | od -An -tx1 | tr -d ' \n'); \
	  if [ "$$magic" != "0061736d" ]; then \
	    echo "FAIL: $$f 非 wasm 产物（magic=$$magic，期望 0061736d）"; \
	    echo "      —— 检查 GOOS/GOARCH 是否生效：WSL 调 Windows go.exe 时不传递，须用 Linux 原生 go 或显式 env"; \
	    exit 1; \
	  fi; \
	  echo "PASS: $$f magic=0061736d(wasm) size=$$(wc -c < "$$f")"; \
	  n=$$((n+1)); \
	done; \
	if [ "$$n" -eq 0 ]; then echo "FAIL: 无 wasm 产物可校验（防门禁空跑）"; exit 1; fi

# secrets-guard —— 明文凭据门禁（口令仅经环境变量注入，严禁入库；T-4 窗口发现 68 件）。
#   三类规则见 scripts/check-secrets.py；既有债务登记于 scripts/secrets-baseline.txt，仅新命中失败。
.PHONY: secrets-guard
secrets-guard:
	@if command -v python3 >/dev/null 2>&1; then P=python3; else P=python; fi; \
	"$$P" scripts/check-secrets.py

# sbom —— 重新生成 CycloneDX 1.5 SBOM（方案 §6.3：主仓与新库各带机器可读 SBOM）。
#   `make sbom` 刷新 sbom.cyclonedx.json（依赖变更后必须刷新，否则 sbom-guard 红）；
#   `make sbom-guard` 只校验"已提交的 SBOM 与当前依赖一致"，供 CI 使用。
SBOM_FILE = sbom.cyclonedx.json

.PHONY: sbom
sbom:
	@if command -v python3 >/dev/null 2>&1; then P=python3; else P=python; fi; \
	"$$P" scripts/gen-sbom.py --out $(SBOM_FILE)

.PHONY: sbom-guard
sbom-guard:
	@if command -v python3 >/dev/null 2>&1; then P=python3; else P=python; fi; \
	test -f $(SBOM_FILE) || { echo "FAIL: 缺 $(SBOM_FILE)，先跑 make sbom"; exit 1; }; \
	TS=$$("$$P" -c "import json;print(json.load(open('$(SBOM_FILE)'))['metadata']['timestamp'])"); \
	SBOM_TIMESTAMP="$$TS" "$$P" scripts/gen-sbom.py --out /tmp/sbom.regen.json >/dev/null; \
	if ! diff -u $(SBOM_FILE) /tmp/sbom.regen.json; then \
	  echo "FAIL: SBOM 与当前 go.mod 依赖不一致 —— 跑 make sbom 并提交"; exit 1; \
	fi; \
	echo "PASS: SBOM 与依赖一致（$$(grep -c '"bom-ref"' $(SBOM_FILE)) 个组件条目）"

# ---- P2-1 T-4：mcp-acl 插件（网关侧工具级 ACL）----
MCP_ACL_PKG = ./gateway/wasm/mcp-acl-plugin/...
MCP_ACL_MAIN_PKG = ./gateway/wasm/mcp-acl-plugin
MCP_ACL_POLICYCACHE_PKG = ./gateway/wasm/mcp-acl-plugin/policycache/

# mcp-acl-test —— 插件单测（policycache 验签/版本/授权矩阵 + 决策分类；渗透用例本地段）
.PHONY: mcp-acl-test
mcp-acl-test:
	$(GO) test -mod=mod -count=1 -cover -timeout 120s $(MCP_ACL_POLICYCACHE_PKG) $(MCP_ACL_PKG)

# mcp-acl-build —— 编译插件 wasm（wasip1 reactor；产物供 OCI/HTTP 分发）
#   构建后自动断言产物 magic（`\0asm`）：封堵「GOOS/GOARCH 未生效 → 静默产出 PE」假绿（T-4 集群窗口）。
.PHONY: mcp-acl-build
mcp-acl-build:
	GOOS=wasip1 GOARCH=wasm $(GO) build -mod=mod -buildmode=c-shared -o gateway/wasm/mcp-acl-plugin/main.wasm $(MCP_ACL_MAIN_PKG)
	@$(MAKE) --no-print-directory wasm-artifact-guard WASM_ARTIFACTS=gateway/wasm/mcp-acl-plugin/main.wasm

# ---- P0-1 多模型智能路由：测试/基准/竞态/E2E ----
ROUTE_ENGINE_PKG = ./gateway/wasm/otpmask-plugin/routeengine/
ROUTE_CACHE_PKG  = ./gateway/wasm/otpmask-plugin/routecache/
ROUTE_PLUGIN_PKG = ./gateway/wasm/otpmask-plugin/

# route-test —— 路由引擎 + 路由缓存单元测试（带覆盖率）
.PHONY: route-test
route-test:
	$(GO) test -count=1 -cover -timeout 120s $(ROUTE_ENGINE_PKG)
	$(GO) test -count=1 -cover -timeout 120s $(ROUTE_CACHE_PKG)

# route-race —— 路由引擎竞态测试（-race，P1-3：评审补充）
# 验证并发场景下 Pick/Record/Tick/Update/Snapshot 混合无数据竞争
.PHONY: route-race
route-race:
	$(GO) test -race -count=1 -run TestRace -timeout 120s $(ROUTE_ENGINE_PKG)

# route-bench —— 路由引擎基准测试（含 10 端点 + 100 端点大规模场景）
.PHONY: route-bench
route-bench:
	$(GO) test -bench=. -benchmem -benchtime=500ms -run=^$$ $(ROUTE_ENGINE_PKG)

# route-bench-scale —— 仅大规模端点基准（100 端点 + 10 优先级组 + 热更新）
.PHONY: route-bench-scale
route-bench-scale:
	$(GO) test -bench="BenchmarkPickEndpoint_100|BenchmarkUpdateConfigSmooth_100|BenchmarkPickEndpoint_10Priority" -benchmem -benchtime=1s -run=^$$ $(ROUTE_ENGINE_PKG)

# route-e2e-build —— 编译路由层 E2E 测试二进制（用于上传到 K8s 节点运行）
# 产物：gateway/wasm/otpmask-plugin/e2e/e2e.test
.PHONY: route-e2e-build
route-e2e-build:
	GOOS=linux GOARCH=amd64 $(GO) test -c -o gateway/wasm/otpmask-plugin/e2e/e2e.test \
		./gateway/wasm/otpmask-plugin/e2e/

# route-e2e —— 本地运行路由层 E2E 测试（需设置 E2E_GATEWAY_URL / E2E_CORE_URL / E2E_API_KEY / E2E_CORE_TOKEN）
.PHONY: route-e2e
route-e2e:
	@: "$${E2E_GATEWAY_URL:?请设置 E2E_GATEWAY_URL 环境变量}"
	@: "$${E2E_CORE_URL:?请设置 E2E_CORE_URL 环境变量}"
	$(GO) test -count=1 -v -timeout 10m ./gateway/wasm/otpmask-plugin/e2e/

# route-chaos —— 混沌测试入口（P0-2：评审补充，本地模拟故障注入）
# 通过模拟端点失败率变化验证熔断/降级/重试的联动正确性
.PHONY: route-chaos
route-chaos:
	$(GO) test -count=1 -v -run "TestE2E_" -timeout 120s $(ROUTE_ENGINE_PKG)
	@echo ""
	@echo "== 混沌测试说明 =="
	@echo "完整混沌测试需在 K8s 环境执行，使用 route-e2e 配合故障注入："
	@echo "  1. 先运行 make route-e2e-build 编译 Linux 二进制"
	@echo "  2. 上传到 K8s 节点，设置 E2E_* 环境变量"
	@echo "  3. 用 chaos-mesh / kubectl 注入故障（网络延迟、5xx、Pod 杀）"
	@echo "  4. 观察熔断/降级/恢复行为是否符合预期"
	@echo "  5. 验证指标：熔断触发时间、恢复时间、降级级别、错误率"

# route-all —— 一键运行路由模块所有质量门禁（单测+竞态+基准+集成）
.PHONY: route-all
route-all: route-test route-race route-bench
	@echo "✅ 路由模块全量门禁通过"

# ---- P0-4 §12.6 profile 切换工具（B5-c）----
# CRYPTOPSVC_URL/ADMIN_URL 缺省指向本机 loopback；ADMIN_TOKEN 须经环境提供（端点强制 admin）。
CRYPTOPSVC_URL ?= http://127.0.0.1:8082
ADMIN_URL      ?= http://127.0.0.1:8081
ADMIN_TOKEN    ?=
FROM           ?=
TO             ?=
MODE           ?=
PRG            ?=
CRYPTO_CONSISTENCY_TARGETS ?=

# cryptop-switch —— 切换/回滚 profile（或仅切 mask_prg）。
#   make cryptop-switch TO=<profile> [FROM=<profile>] [MODE=restart|hot] [PRG=hmac-sha256|sm4|bridge]
# FROM 缺省经 sidecar /v1/capabilities 探测当前生效 profile。
.PHONY: cryptop-switch
cryptop-switch:
	@: "$${TO:?用法: make cryptop-switch TO=<profile> [MODE=...] [PRG=...]}"
	@FROM="$(FROM)"; \
	if [ -z "$$FROM" ]; then \
	  FROM=$$(curl -fsS --max-time 2 "$(CRYPTOPSVC_URL)/v1/capabilities" \
	    | sed -n 's/.*"profile":"\([^"]*\)".*/\1/p'); \
	fi; \
	[ -n "$$FROM" ] || { echo "无法探测当前 profile：显式传 FROM= 或检查 CRYPTOPSVC_URL" >&2; exit 1; }; \
	FROM="$$FROM" TO="$(TO)" MODE="$(MODE)" PRG="$(PRG)" \
	ADMIN="$(ADMIN_URL)" ADMIN_TOKEN="$(ADMIN_TOKEN)" \
	CRYPTOPSVC_URL="$(CRYPTOPSVC_URL)" \
	bash scripts/cryptop-switch-profile.sh

# cryptop-verify —— 全域一致性校验（§7.5；TO 缺省仅校验合法矩阵不比对 profile）。
.PHONY: cryptop-verify
cryptop-verify:
	@CRYPTOPSVC_URL="$(CRYPTOPSVC_URL)" \
	CRYPTO_CONSISTENCY_TARGETS="$(CRYPTO_CONSISTENCY_TARGETS)" \
	bash scripts/cryptop-verify-consistency.sh "$(TO)"

# tlcp-certgen —— 生成 SM2 根 + TLCP 签名/加密双证书（§12.4；产物 deploy/tlcp/certs，
# *.crt/*.key 已被 gitignore 不入库）。
.PHONY: tlcp-certgen
tlcp-certgen:
	go run ./deploy/tlcp/certgen/ -out deploy/tlcp/certs

# tlcp-verify —— T-12.4-1..3 断言 + 证据 JSON（§12.4；需 Tongsuo/网关在跑，
# 退出码 7 = 本机无 Tongsuo 全 SKIP，1 = 断言失败）。
#   make tlcp-verify [GATEWAY_HOST=...] [GATEWAY_PORT=...] [ENVELOPE_FILE=...]
.PHONY: tlcp-verify
tlcp-verify:
	GATEWAY_HOST="$${GATEWAY_HOST:-127.0.0.1}" GATEWAY_PORT="$${GATEWAY_PORT:-443}" \
	ENVELOPE_FILE="$${ENVELOPE_FILE:-}" TONGSUO_BIN="$${TONGSUO_BIN:-tongsuo}" \
	bash deploy/tlcp/verify.sh

# tlcp-certgen-prod —— 生产证书生成（P1-5 S3-c/M7-1；有效期默认 365 天，符合密评 ≤1 年建议 R2-09）。
# 私钥须随后改由密钥托管/Secret 注入并禁止入库（§6.6 证书管理）。
#   make tlcp-certgen-prod [TLCP_DAYS=365] [TLCP_CN=tlcp-gateway.local]
.PHONY: tlcp-certgen-prod
tlcp-certgen-prod:
	go run ./deploy/tlcp/certgen/ -out deploy/tlcp/certs -days "$${TLCP_DAYS:-365}" -cn "$${TLCP_CN:-tlcp-gateway.local}"

# drill —— §13 国密切换演练（T-13.1 脚本化；§13.2 八步编排）。
# 环境特定步骤经环境变量注入，缺省 SKIP：
#   PLUGIN_PROBE_URL=<插件探活 URL> DRILL_FUNCTION_CMD=<功能回归命令> \
#   DRILL_DUALREAD_CMD=<双读命令> DRILL_PERF_CMD=<基准命令>
#   [START_PROFILE=intl] [DRILL_OUT=deploy/drill-runs]
.PHONY: drill
drill:
	@: "$${ADMIN_TOKEN:?用法: make drill ADMIN_TOKEN=<admin token>}"
	ADMIN="$${ADMIN:-http://127.0.0.1:8081}" \
	CRYPTOPSVC_URL="$${CRYPTOPSVC_URL:-http://127.0.0.1:8082}" \
	START_PROFILE="$${START_PROFILE:-intl}" \
	PLUGIN_PROBE_URL="$${PLUGIN_PROBE_URL:-}" \
	DRILL_FUNCTION_CMD="$${DRILL_FUNCTION_CMD:-}" \
	DRILL_DUALREAD_CMD="$${DRILL_DUALREAD_CMD:-}" \
	DRILL_PERF_CMD="$${DRILL_PERF_CMD:-}" \
	DRILL_OUT="$${DRILL_OUT:-deploy/drill-runs}" \
	bash scripts/cryptop-drill.sh

# cache-canary —— P0-2 §12 缓存灰度：放量门禁校验 + 证据 + 回滚指引（G3）。
# 偏差：灰度配置下发热更新未接线，本目标只做门禁/证据/回滚指引，不下发配置。
#   make cache-canary ARGS="--stage G-2"        # 校验阶段门禁（需 CACHE_METRICS_URL）
#   make cache-canary ARGS="--rollback --to G-1" # 回滚动作指引
.PHONY: cache-canary
cache-canary:
	@CACHE_METRICS_URL="$${CACHE_METRICS_URL:-}" \
	CACHE_CANARY_OUT="$${CACHE_CANARY_OUT:-deploy/cache-canary-runs}" \
	EXACT_P95_BUDGET_MS="$${EXACT_P95_BUDGET_MS:-1}" \
	bash scripts/cache-canary.sh $${ARGS:-}

# ---------------------------------------------------------------------------
# 密态大模型适配器（confllm-adapter）—— 密态大模型接入（T05 / 设计 §7 QA-4、QA-5）
# 设计约束：库内可独立 go test，零硬依赖 admin-service。
#   make test-adapters              # 离线契约/单元测试（mock 内核 + fixture，不触外网、不需凭据）
#   make test-adapters-integration  # 集成测试（需 go 1.26 + 真实凭据/联网，-tags=integration 门控）
# ---------------------------------------------------------------------------
CONFLLM_PKG := ./gateway/confllm-adapter/...
CONFLLM_ADMIN_PKG := ./gateway/gateway-admin-service/...

.PHONY: test-adapters test-adapters-integration
# 离线契约/单元测试：-count=1 防 (cached) 假绿；-race 抓数据竞争（§7.10 T05）。
# -mod=mod：仓库含 vendor/ 但无 modules.txt，裸 go 会 inconsistent vendoring（CI 同此约束）。
test-adapters:
	go test -count=1 -race -mod=mod $(CONFLLM_PKG)

# 集成测试：需 go 1.26 + 真实凭据/联网；-tags=integration 门控。
# 覆盖库内 + admin-service 接线/富化/既有 model_catalog_test.go 3 用例回归（§7.10 QA2-24）。
test-adapters-integration:
	go test -count=1 -race -mod=mod -tags=integration -timeout=180s $(CONFLLM_PKG) $(CONFLLM_ADMIN_PKG)

# ---------------------------------------------------------------------------
# 路线2（掩码像推理）打包 —— 详见 packaging/route2/README.md
#   make route2-build   构建 dist/tee-infer-service + dist/route2-client（纯 CPU）
#   make route2-image   构建 docker compose 镜像
#   make route2-smoke   对已运行的 tee-infer 跑端到端冒烟
# ---------------------------------------------------------------------------
.PHONY: route2-build
route2-build:
	bash packaging/route2/build.sh

.PHONY: route2-image
route2-image:
	docker compose -f packaging/route2/docker-compose.yaml build

.PHONY: route2-smoke
route2-smoke:
	bash packaging/route2/smoke.sh
