# tee-infer-service 镜像（M5）
FROM golang:1.26-alpine AS build
WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct
COPY go.mod go.sum ./
RUN go mod download
COPY cipher ./cipher
COPY protocol ./protocol
COPY internal ./internal
# 路线2 引擎（masked-infer）已拆分为独立仓库 github.com/FengYang/masked-infer。
# 本镜像构建时该模块须可达：发布后由 go.mod 正式 require（去掉本地 replace）经 proxy 拉取；
# 本地构建须把 masked-infer 源码拷入构建上下文（或挂载），否则 go build 无法解析 masked-infer。
COPY gateway/cryptop ./gateway/cryptop
COPY gateway/tee-infer-service ./gateway/tee-infer-service
# 补全导入树：main.go/audit_export.go 依赖 auditexport（审计导出），mcp_config.go 等依赖
# mcpsec（MCP 安全）。缺这两处 COPY 会导致 go build 直接失败（历史 Dockerfile 失效点）。
COPY gateway/auditexport ./gateway/auditexport
COPY gateway/mcpsec ./gateway/mcpsec
RUN CGO_ENABLED=0 go build -mod=mod -trimpath -o /out/tee-infer-service ./gateway/tee-infer-service

FROM alpine:3.20
COPY --from=build /out/tee-infer-service /usr/local/bin/tee-infer-service
# OG-9 策略/词库资产（31 个 JSON，~76KB）随镜像只读分发；
# readOnlyRootFilesystem 下只读不冲突，热加载（POST /config/policy/reload）重读同目录。
COPY gateway/tee-infer-service/policy /app/policy
# Phala C-MaaS 为 HTTPS：alpine 基础镜像自带 ca-certificates-bundle，此处显式兜底防精简基础镜像。
RUN apk add --no-cache ca-certificates
# 非 root 运行：deploy/k8s 与 deploy/tee 清单均置 runAsNonRoot（P0b 实测：镜像默认 root 会被 kubelet 拒绝创建）
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/tee-infer-service"]
