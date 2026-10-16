# P1-7 T2c（D-20 候选 ii）：审计回灌「极薄签名器」镜像。
#
# 职责：读 Fluent Bit 批次 → 整形为 /audit/report 契约 → HMAC 签名 → POST 上报。
# 只依赖标准库，构建不需下载第三方模块。
#
# 用法：
#   docker build -t audit-sign-relay:latest -f cmd/audit-sign-relay/Dockerfile .
#   docker run --rm -p 9090:9090 -e AUDIT_REPORT_TOKEN=<上报令牌> \
#     -e AUDIT_REPORT_URL=http://tee-infer-service.otpmask.svc.cluster.local:19090/audit/report \
#     audit-sign-relay:latest
#
# ⚠️ 部署约束见 main.go 包注释：仅本地通道、令牌走 Secret、丢弃可观测不补链。

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd/audit-sign-relay/ ./cmd/audit-sign-relay/
# 仅编译本包（纯标准库依赖）；CGO 关闭 + trimpath 便于可复现构建。
RUN CGO_ENABLED=0 GOFLAGS=-mod=mod go build -trimpath -o /out/audit-sign-relay ./cmd/audit-sign-relay

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/audit-sign-relay /usr/local/bin/audit-sign-relay
# 非 root 运行；9090 为非特权端口，无需 CAP_NET_BIND_SERVICE。
USER 65534:65534
EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/audit-sign-relay"]
