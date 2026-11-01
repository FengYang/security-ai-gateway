#!/usr/bin/env bash
# 路线2 单机 Linux 安装：构建镜像 → 起 tee-infer → 等健康 → 跑 route2-client 冒烟。
# 前置：已安装 Docker Engine + docker compose v2（docker compose version 可用）。
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v docker >/dev/null 2>&1; then
  echo "错误：未安装 docker。请先安装 Docker Engine。" >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "错误：未安装 docker compose v2 插件（docker compose）。" >&2
  exit 1
fi

echo "==> 构建镜像（tee-infer-service + route2-client）"
docker compose -f docker-compose.yaml build

echo "==> 启动 tee-infer-service"
docker compose -f docker-compose.yaml up -d tee-infer

cid="$(docker compose -f docker-compose.yaml ps -q tee-infer || true)"
if [ -z "$cid" ]; then
  echo "错误：tee-infer 容器未创建。" >&2
  exit 1
fi

echo "==> 等待健康检查（最多 120s）"
st=unknown
for _ in $(seq 1 60); do
  st="$(docker inspect --format '{{.State.Health.Status}}' "$cid" 2>/dev/null || echo unknown)"
  [ "$st" = "healthy" ] && break
  sleep 2
done
if [ "$st" != "healthy" ]; then
  echo "错误：tee-infer 未就绪（health=$st）。日志：" >&2
  docker compose -f docker-compose.yaml logs --tail=60 tee-infer >&2 || true
  exit 1
fi
echo "==> tee-infer 已就绪"

echo "==> 运行 route2-client 端到端冒烟"
docker compose -f docker-compose.yaml run --rm route2-client

echo "==> 完成。服务仍在运行：docker compose -f docker-compose.yaml ps"
echo "    停止：docker compose -f docker-compose.yaml down"
