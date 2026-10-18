# P2-1 T-2 样例 MCP 后端 —— 备选镜像路径（需可用 Docker 与网络）。
# 离线主路径：build-images.py（纯 Python + Go 交叉编译，无需 Docker）。
#
# 用法（仓库根目录）：
#   docker build -f deploy/samples/mcp-backends/Dockerfile --build-arg SRC=demo       -t otpmask/mcp-demo:0.1.0 .
#   docker build -f deploy/samples/mcp-backends/Dockerfile --build-arg SRC=filesystem -t otpmask/mcp-fs:0.1.0 .
FROM golang:1.26 AS build
ARG SRC=demo
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/app ./deploy/samples/mcp-backends/${SRC}

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/app /app
EXPOSE 8080
ENTRYPOINT ["/app"]
