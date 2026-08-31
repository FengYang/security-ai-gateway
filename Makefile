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
