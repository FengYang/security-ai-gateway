# cryptopsvc 镜像（P0-4 §12.1：插件密码唯一 HTTP 面，sidecar 与 Envoy 同 Pod）
FROM golang:1.25-alpine AS build
WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct
COPY go.mod go.sum ./
RUN go mod download
COPY cipher ./cipher
COPY internal ./internal
COPY gateway/cryptop ./gateway/cryptop
COPY gateway/cryptopsvc ./gateway/cryptopsvc
# R-2/R-14/R-16/R-20/R-21 启动校验在二进制内；CGO 关闭，静态分发。
RUN CGO_ENABLED=0 go build -trimpath -o /out/cryptopsvc ./gateway/cryptopsvc/cmd/cryptopsvc

FROM alpine:3.20
COPY --from=build /out/cryptopsvc /usr/local/bin/cryptopsvc
# 非 root（与 deploy/k8s、deploy/helm、deploy/higress 注入补丁 runAsNonRoot 对齐）。
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/cryptopsvc"]
