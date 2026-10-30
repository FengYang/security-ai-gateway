# gateway-core 镜像（控制面：处方/路由表/限流预算表签发 + 策略变更审计）
#
# 构建（仓库根执行）：
#   docker build -t security-ai-gateway/gateway-core:latest -f gateway/gateway-core/Dockerfile .
#
# 说明：
#   - 非测试依赖为这四处：`gateway/gateway-core/**`、`gateway/mcpsec`（K_tx/K_rx 同族签名器）、
#     `gateway/rxroute`（路由表结构与验签，跨模块共用；仅测试引用的 `wasm/otpmask-plugin/routecache` 不需 COPY）、
#     `gateway/cryptop`（策略变更审计的密码运行时）；
#   - 启动强校验：OTP_CORE_SIG_KEY 缺失或非 ≥32 字节 hex → **拒绝启动**（fail-fast）。
#     该密钥即插件侧 `route_verify_key`（K_rx），两侧必须一致，否则插件拉表验签失败（保留旧表）；
#   - OTP_CORE_AUTH_TOKEN 缺省必须设置，否则**拒绝启动**（fail-closed：控制面必须鉴权）；
#     仅本地调试可用 OTP_CORE_INSECURE_NOAUTH=true 显式关闭（严禁生产/集群使用；本目录清单已配）；
#   - 运行镜像装 ca-certificates：OTP_CORE_TEE_URL 若指向 HTTPS 的 tee-infer 需要；
#   - USER 65532 与清单 runAsUser/runAsGroup 一致（least privilege）；
#     清单另置 readOnlyRootFilesystem=true → 审计文件目录由 emptyDir/PVC 挂载提供。
FROM golang:1.26-alpine AS build
WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct
COPY go.mod go.sum ./
RUN go mod download
COPY gateway/gateway-core ./gateway/gateway-core
COPY gateway/mcpsec ./gateway/mcpsec
COPY gateway/rxroute ./gateway/rxroute
COPY gateway/cryptop ./gateway/cryptop
RUN CGO_ENABLED=0 go build -trimpath -o /out/gateway-core ./gateway/gateway-core/cmd

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/gateway-core /usr/local/bin/gateway-core
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/gateway-core"]
