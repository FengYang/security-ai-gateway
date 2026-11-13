# gateway-admin-service 镜像（M2 A-2：管理门户业务服务 + 内部凭据 broker）
#
# 构建（仓库根执行）：
#   docker build -t security-ai-gateway/gateway-admin-service:latest -f gateway/gateway-admin-service/Dockerfile .
#
# 说明：
#   - 依赖本目录 + `gateway/cryptop`（密码运行时）+ `gateway/confllm-adapter`（密态大模型适配器，
#     由 confllm_policy.go / confllm_wire.go 直接引用）+ `protocol/go`（tracing/审计帧），故需 COPY 四处；
#   - 运行镜像安装 ca-certificates：broker 需出网访问厂商 HTTPS 端点
#     （NetworkPolicy 已限定仅 443 且排除集群内网段，见 deploy/k8s/gateway-admin-service.yaml）；
#   - USER 65532 与清单 runAsUser/fsGroup 一致（least privilege；清单另置
#     readOnlyRootFilesystem=true、capabilities.drop=[ALL]）→ 审计默认内存态，无需可写根目录。
FROM golang:1.26-alpine AS build
WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct
COPY go.mod go.sum ./
RUN go mod download
COPY gateway/gateway-admin-service ./gateway/gateway-admin-service
COPY gateway/cryptop ./gateway/cryptop
COPY gateway/confllm-adapter ./gateway/confllm-adapter
COPY protocol ./protocol
RUN CGO_ENABLED=0 go build -trimpath -o /out/gateway-admin-service ./gateway/gateway-admin-service

FROM alpine:3.20
# 运行阶段先做一次 `apk upgrade`：基础镜像把包钉在快照版本上（alpine:3.20.10 自带
# musl/musl-utils 1.2.5-r3），而同一 3.20 分支已发布带修复的 r4（CVE-2026-107891：
# musl regcomp 整数溢出可致任意代码执行）。不 upgrade 则 trivy 镜像门禁
# （HIGH/CRITICAL + ignore-unfixed）必红——patch 级重建包属同一分支内的正常修复，
# 不改变运行特性，故就地升级而非放宽门禁。
# 另注：3.20 分支已于 2026-04-01 结束支持（alpine 官方 releases 页），
# 「是否把基底升到当前稳定分支」属发布物变更，另行按决策项跟踪。
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates
COPY --from=build /out/gateway-admin-service /usr/local/bin/gateway-admin-service
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/gateway-admin-service"]
