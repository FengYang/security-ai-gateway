# Build from the repository root:
#   docker build -f gateway/a2aproxy/Dockerfile -t security-ai-gateway/a2aproxy:lan .
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY gateway ./gateway
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/a2aproxy ./gateway/a2aproxy/cmd

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /out/a2aproxy /usr/local/bin/a2aproxy
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/a2aproxy"]
