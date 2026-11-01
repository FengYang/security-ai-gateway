#!/usr/bin/env bash
# 对已运行的 tee-infer-service 执行一次路线2 端到端冒烟（经容器内 route2-client）。
# 用法：bash packaging/route2/smoke.sh
#   SERVER=http://host:19090 DIM=32 LAYERS=4 bash packaging/route2/smoke.sh
set -euo pipefail
cd "$(dirname "$0")"
SERVER="${SERVER:-http://tee-infer:19090}"
DIM="${DIM:-32}"
LAYERS="${LAYERS:-4}"
docker compose -f docker-compose.yaml run --rm route2-client \
  -server "$SERVER" -dim "$DIM" -layers "$LAYERS"
