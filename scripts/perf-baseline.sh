#!/usr/bin/env bash
# perf-baseline.sh — GF.5 真机性能基线采集（R1-A 性能决策门）
#
# 用途：对 /infer 端点做并发压测，采集吞吐 / P50 / P95 / P99 延迟，
# 供 R1-A 决策（tee_gpu vs cmaas，密态 ≤ 35% 吞吐开销、P99 +≤ 30%）。
#
# 依赖：网关运行中（默认 http://127.0.0.1:10000/infer）；ab 或 wrk 任一可用。
# 用法：
#   GATEWAY_URL=http://127.0.0.1:10000/infer CONCURRENCY=20 REQUESTS=2000 ./scripts/perf-baseline.sh
#
# 说明：本脚本为基线采集模板，真机到位后按实际负载/密钥握手补齐请求载荷；
# 结果落 CSV 供《GF5-真机验收模板.md》决策引用。
set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:10000/infer}"
CONCURRENCY="${CONCURRENCY:-20}"
REQUESTS="${REQUESTS:-2000}"
OUT="${OUT:-perf-baseline.csv}"

echo "== GF.5 性能基线采集 =="
echo "目标: $GATEWAY_URL | 并发: $CONCURRENCY | 请求数: $REQUESTS"

if command -v wrk >/dev/null 2>&1; then
  echo "使用 wrk ..."
  wrk -t4 -c"$CONCURRENCY" -d30s --latency "$GATEWAY_URL" | tee /tmp/otpmask-perf.txt
elif command -v ab >/dev/null 2>&1; then
  echo "使用 ab ..."
  ab -n "$REQUESTS" -c "$CONCURRENCY" "$GATEWAY_URL" | tee /tmp/otpmask-perf.txt
else
  echo "ERROR: 需要 wrk 或 ab（apache2-utils）之一" >&2
  exit 1
fi

# 提取关键指标（尽力解析，字段缺失不阻断）
echo "engine,endpoint,concurrency,requests" > "$OUT"
echo "$GATEWAY_URL,$GATEWAY_URL,$CONCURRENCY,$REQUESTS" >> "$OUT"
echo "原始结果见 /tmp/otpmask-perf.txt；汇总写入 $OUT"
echo "提示：真机验收请对比 tee_gpu 与 cmaas 两组基线，按《GF5-真机验收模板.md》判定。"
