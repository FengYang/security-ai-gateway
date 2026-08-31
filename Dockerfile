# syntax=docker/dockerfile:1
# OTP-Mask 安全聚合 — 多阶段构建
# 产物：party（参与方服务）与 aggregator（聚合服务器）两个二进制。
#
# 用法：
#   docker build -t otpmask:latest .
#   docker run -d --name party0 otpmask:latest party -listen :9000 -id 0 -n 4 -t 3 -dim 8 -input '[100,200]' -tls-cert /certs/server.crt -tls-key /certs/server.key -tls-client-ca /certs/ca.crt
#   docker run -d --name agg  otpmask:latest aggregator -n 4 -t 3 -dim 8 -addr party0:9000,party1:9000,... -tls-cert /certs/client.crt -tls-key /certs/client.key -tls-ca /certs/ca.crt -tls-server-name party0

FROM golang:1.25-alpine AS build
WORKDIR /src
# 依赖缓存层：仅复制 go.mod/go.sum，利用 Docker 层缓存加速构建
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO 关闭：静态链接，便于最小化运行镜像（纯 Go 无 cgo 依赖）
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/party ./cmd/party && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/aggregator ./cmd/aggregator

FROM alpine:3.20
# 非 root 运行：最小权限原则
RUN addgroup -S otpmask && adduser -S -G otpmask otpmask
COPY --from=build /out/party /usr/local/bin/party
COPY --from=build /out/aggregator /usr/local/bin/aggregator
USER otpmask
# 不设 ENTRYPOINT：调用方显式指定子命令（party / aggregator），
# 见文件头部用法示例（命令作为容器参数传入）。
CMD ["party", "-h"]
