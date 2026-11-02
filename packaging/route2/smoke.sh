#!/usr/bin/env bash
# 对已运行的 tee-infer-service 执行一次路线2 端到端冒烟（经容器内 route2-client）。
# 走 proto=2 plan 驱动路径：attest → ECDH → complete → prefill（批量 KV，prompt-len>1
# 覆盖 K-run/V-run 配对通路）→ decode 逐 token 生成。
# 用法：bash packaging/route2/smoke.sh
#   SERVER=http://host:19090 PROMPT=4 GEN=2 bash packaging/route2/smoke.sh
set -euo pipefail
cd "$(dirname "$0")"
SERVER="${SERVER:-http://tee-infer:19090}"
MODEL="${MODEL:-route2-demo-tiny}"
PROMPT="${PROMPT:-4}"
GEN="${GEN:-2}"
docker compose -f docker-compose.yaml run --rm route2-client \
  -server "$SERVER" -model "$MODEL" -prompt-len "$PROMPT" -gen "$GEN"
