# Build from the repository root:
#   docker build -f gateway/a2aguardrail/Dockerfile -t security-ai-gateway/a2a-guardrail:lan .
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY gateway ./gateway
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/a2aguardrail ./gateway/a2aguardrail/cmd/a2aguardrail

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /out/a2aguardrail /usr/local/bin/a2aguardrail
COPY gateway/tee-infer-service/policy/categories.json /app/policy/categories.json
COPY gateway/tee-infer-service/policy/manifest.json /app/policy/manifest.json
COPY gateway/tee-infer-service/policy/keywords /app/policy/keywords
COPY gateway/tee-infer-service/policy/regex /app/policy/regex
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/a2aguardrail"]
