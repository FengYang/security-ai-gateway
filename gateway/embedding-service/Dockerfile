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
ENTRYPOINT ["/usr/local/bin/embedding-service"]
