# attest-verify 镜像（P1-8 T1 部署接线：证明验证 sidecar，与 Envoy 同 Pod）
FROM golang:1.26-alpine AS build
WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct
COPY go.mod go.sum ./
RUN go mod download
COPY cipher ./cipher
COPY internal ./internal
COPY gateway/cryptop ./gateway/cryptop
COPY gateway/attest-verify ./gateway/attest-verify
# CGO 关闭，静态分发；go-tdx-guest 纯 Go 实现，无 C 依赖
RUN CGO_ENABLED=0 go build -trimpath -mod=mod -o /out/attest-verify ./gateway/attest-verify/cmd/attest-verify

FROM alpine:3.20
COPY --from=build /out/attest-verify /usr/local/bin/attest-verify
# 非 root（与 deploy/higress sidecar 注入补丁 runAsNonRoot 对齐）
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/attest-verify"]
