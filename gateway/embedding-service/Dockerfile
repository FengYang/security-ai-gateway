# embedding-service 镜像（M4）
FROM golang:1.25-alpine AS build
WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct
COPY go.mod go.sum ./
RUN go mod download
COPY gateway/embedding-service ./gateway/embedding-service
RUN CGO_ENABLED=0 go build -trimpath -o /out/embedding-service ./gateway/embedding-service

FROM alpine:3.20
COPY --from=build /out/embedding-service /usr/local/bin/embedding-service
# 非 root 运行：deploy/k8s 与 deploy/helm 清单均置 runAsNonRoot（P0b 实测：镜像默认 root 会被 kubelet 拒绝创建）
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/embedding-service"]
