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
.PHONY: wasm-guard
wasm-guard:
	@echo "== wasm-guard 断言①a：插件源码 direct import 零密码（R-11/§9.1）=="
	@out=$$($(GO) list -f '{{range .Imports}}{{.}}{{"\n"}}{{end}}' ./gateway/wasm/otpmask-plugin/... | grep -E '^(crypto/|github.com/emmansun/gmsm|security-ai-gateway/cipher/mask|security-ai-gateway/protocol/go/cryptoops)' | sort -u || true); \
	if [ -n "$$out" ]; then echo "FAIL: 插件源码直接 import 密码包——"; echo "$$out"; exit 1; fi; \
	echo "PASS: 插件源码零密码 import"
	@echo "== wasm-guard 断言①b：闭包内本仓包与 gmsm 无密码 =="
	@badmod=$$($(GO) list -deps -f '{{.ImportPath}}' ./gateway/wasm/otpmask-plugin/... | grep -E '^github.com/emmansun/gmsm' || true); \
	if [ -n "$$badmod" ]; then echo "FAIL: 插件链入 gmsm——"; echo "$$badmod"; exit 1; fi; \
	bad=$$($(GO) list -deps -f '{{.ImportPath}} {{range .Imports}}{{.}} {{end}}' ./gateway/wasm/otpmask-plugin/... | grep -E '^security-ai-gateway/' | grep -E ' (crypto/[a-z0-9/]+|github\.com/emmansun/gmsm|security-ai-gateway/cipher/mask|security-ai-gateway/protocol/go/cryptoops)( |$$)' || true); \
	if [ -n "$$bad" ]; then echo "FAIL: 闭包内本仓包链入密码求值包——"; echo "$$bad"; exit 1; fi; \
	echo "PASS: 闭包内本仓包零密码"
	@echo "== wasm-guard 断言②：protocol/go framing 包零密码不变量 =="
	@out=$$($(GO) list -deps -f '{{.ImportPath}}' security-ai-gateway/protocol/go | grep -E '(^crypto/(aes|cipher|hmac|sha256|sha512|ecdh|ecdsa)|gmsm)' || true); \
	if [ -n "$$out" ]; then echo "FAIL: protocol/go 链入密码包——"; echo "$$out"; exit 1; fi; \
	echo "PASS: protocol/go 零密码"

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
