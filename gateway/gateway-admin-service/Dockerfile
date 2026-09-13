# gateway-admin-service 镜像（M2 A-2：管理门户业务服务 + 内部凭据 broker）
#
# 构建（仓库根执行）：
#   docker build -t security-ai-gateway/gateway-admin-service:latest -f gateway/gateway-admin-service/Dockerfile .
#
# 说明：
#   - 该包仅依赖标准库（无内部/第三方 import），故只需 go.mod/go.sum + 本目录；
#   - 运行镜像安装 ca-certificates：broker 需出网访问厂商 HTTPS 端点
#     （NetworkPolicy 已限定仅 443 且排除集群内网段，见 deploy/k8s/gateway-admin-service.yaml）；
#   - USER 65532 与清单 runAsUser/fsGroup 一致（least privilege；清单另置
#     readOnlyRootFilesystem=true、capabilities.drop=[ALL]）→ 审计默认内存态，无需可写根目录。
FROM golang:1.25-alpine AS build
WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct
COPY go.mod go.sum ./
RUN go mod download
COPY gateway/gateway-admin-service ./gateway/gateway-admin-service
RUN CGO_ENABLED=0 go build -trimpath -o /out/gateway-admin-service ./gateway/gateway-admin-service

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/gateway-admin-service /usr/local/bin/gateway-admin-service
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/gateway-admin-service"]
