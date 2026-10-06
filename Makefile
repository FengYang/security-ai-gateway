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
