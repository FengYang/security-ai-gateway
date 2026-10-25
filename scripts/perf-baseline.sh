#!/usr/bin/env bash
# perf-baseline.sh — GF.5 真机性能基线采集（R1-A 性能决策门，评审 P1-5 场景固化）
#
# 场景矩阵（固定，禁止临场增删；变更需评审并记录）：
#   prompt  : short（≤100 token）/ long（≥2k token）
#   mode    : stream（SSE 流式）/ non-stream（单分片聚合）
#   conc    : 16 / 64
#   chain   : enc（密态全链路：网关→otpmask→tee-infer）/ plain（明文基线：直连引擎）
# 共 2×2×2×2 = 16 组；enc 与 plain 对照得出加密链开销。
#
# 决策门（R1-A）：密态吞吐开销 ≤ 35%、P99 劣化 ≤ +30%（tee_gpu vs cmaas 另行对比）。
# 结果落 docs/benchmark/<date>-r1a/*.csv，供《GF5-真机验收模板.md》决策引用。
#
# 依赖：wrk 或 ab 任一可用；密态链路网关运行中；明文基线引擎直连地址可达。
# 用法：
#   GATEWAY_URL=http://127.0.0.1:10000 ENGINE_URL=http://127.0.0.1:8000 \
#   DURATION=30s OUT_DIR=docs/benchmark/r1a ./scripts/perf-baseline.sh
#
# 说明：密态请求需完整段① 会话（attest→key/issue→kenc/ksig 信封），本脚本为
# 真机模板——PAYLOAD_SHORT/PAYLOAD_LONG 提供请求体文件挂点，真机到位后按
# 实际会话流程补齐（与 pen_test.py 同源的请求构造可复用）。
set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:10000}"   # 密态全链路入口（/infer）
ENGINE_URL="${ENGINE_URL:-}"                            # 明文基线：引擎直连地址（必填，用于 enc/plain 对照）
DURATION="${DURATION:-30s}"
OUT_DIR="${OUT_DIR:-docs/benchmark/r1a}"
PAYLOAD_SHORT="${PAYLOAD_SHORT:-}"   # 短 prompt 请求体文件（≤100 token）
PAYLOAD_LONG="${PAYLOAD_LONG:-}"     # 长 prompt 请求体文件（≥2k token）

PROMPTS="short long"
MODES="stream non-stream"
CONCS="16 64"
CHAINS="enc plain"

command -v wrk >/dev/null 2>&1 && TOOL=wrk || command -v ab >/dev/null 2>&1 && TOOL=ab || {
  echo "ERROR: 需要 wrk 或 ab（apache2-utils）之一" >&2; exit 1; }

if [ -z "$ENGINE_URL" ]; then
  echo "ERROR: 明文基线 ENGINE_URL 必填（enc/plain 对照是 R1-A 决策门的必要项）" >&2; exit 1
fi
if [ -z "$PAYLOAD_SHORT" ] || [ -z "$PAYLOAD_LONG" ]; then
  echo "ERROR: PAYLOAD_SHORT / PAYLOAD_LONG 请求体文件必填（真机到位后按段① 会话构造）" >&2; exit 1
fi

mkdir -p "$OUT_DIR"
RAW="$OUT_DIR/raw"; mkdir -p "$RAW"
CSV="$OUT_DIR/r1a-baseline.csv"

echo "== GF.5 R1-A 性能基线（场景矩阵固化版） =="
echo "工具: $TOOL | 时长: $DURATION | 输出: $CSV"

# 请求体选择（短/长 prompt）
payload_for() { [ "$1" = "short" ] && echo "$PAYLOAD_SHORT" || echo "$PAYLOAD_LONG"; }
# 目标 URL 选择（enc=密态网关 / plain=引擎直连）
url_for()     { [ "$1" = "enc" ] && echo "$GATEWAY_URL" || echo "$ENGINE_URL"; }

run_one() { # $1=prompt $2=mode $3=conc $4=chain → 追加一行 CSV
  local prompt="$1" mode="$2" conc="$3" chain="$4"
  local url; url="$(url_for "$chain")"
  local body; body="$(payload_for "$prompt")"
  local tag="${prompt}-${mode}-c${conc}-${chain}"
  local raw="$RAW/${tag}.txt"
  echo "-- [$tag] $url"
  if [ "$TOOL" = "wrk" ]; then
    # stream: 保持连接全程接收 SSE；non-stream: 等待完整响应（对 /infer 即单分片）
    if [ "$mode" = "stream" ]; then
      wrk -t4 -c"$conc" -d"$DURATION" --latency -s "${WRK_SCRIPT:-/dev/null}" "$url" >"$raw" 2>&1 || true
    else
      wrk -t4 -c"$conc" -d"$DURATION" --latency "$url" >"$raw" 2>&1 || true
    fi
    # wrk 输出解析：Requests/sec、Latency 分布（尽力解析，字段缺失记 NA）
    local rps p50 p99
    rps=$(grep -oE 'Requests/sec: *[0-9.]+' "$raw" | grep -oE '[0-9.]+' || echo NA)
    p50=$(grep -E '^\s*50%\s' "$raw" | grep -oE '[0-9.]+[muni]*s?' | head -1 || echo NA)
    p99=$(grep -E '^\s*99%\s' "$raw" | grep -oE '[0-9.]+[muni]*s?' | head -1 || echo NA)
    echo "$tag,$prompt,$mode,$conc,$chain,$rps,$p50,$p99" >> "$CSV"
  else
    ab -n "${REQUESTS:-2000}" -c"$conc" -p "$body" -T 'application/json' "$url" >"$raw" 2>&1 || true
    local rps p50 p99
    rps=$(grep -oE 'Requests per second: *[0-9.]+' "$raw" | grep -oE '[0-9.]+' || echo NA)
    p50=$(grep -E '^\s*50%' "$raw" | awk '{print $2}' || echo NA)
    p99=$(grep -E '^\s*99%' "$raw" | awk '{print $2}' || echo NA)
    echo "$tag,$prompt,$mode,$conc,$chain,$rps,$p50,$p99" >> "$CSV"
  fi
}

echo "tag,prompt,mode,concurrency,chain,rps,p50,p99" > "$CSV"
for prompt in $PROMPTS; do
  for mode in $MODES; do
    for conc in $CONCS; do
      for chain in $CHAINS; do
        run_one "$prompt" "$mode" "$conc" "$chain"
      done
    done
  done
done

echo "== 完成：$CSV =="
echo "决策门（R1-A）：密态（enc）对明文（plain）吞吐开销 ≤ 35%、P99 劣化 ≤ +30%。"
echo "后续：对 tee_gpu 与 cmaas 各跑一轮本矩阵，结果与结论落 docs/benchmark/，"
echo "      按《docs/GF5-真机验收模板.md》判定生产主路径。"
