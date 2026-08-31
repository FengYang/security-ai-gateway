# tee-infer-service 镜像（M5）
FROM golang:1.25-alpine AS build
WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct
COPY go.mod go.sum ./
RUN go mod download
COPY cipher ./cipher
COPY protocol ./protocol
COPY internal ./internal
COPY gateway/teecore ./gateway/teecore
COPY gateway/tee-infer-service ./gateway/tee-infer-service
RUN CGO_ENABLED=0 go build -trimpath -o /out/tee-infer-service ./gateway/tee-infer-service

FROM alpine:3.20
COPY --from=build /out/tee-infer-service /usr/local/bin/tee-infer-service
ENTRYPOINT ["/usr/local/bin/tee-infer-service"]
