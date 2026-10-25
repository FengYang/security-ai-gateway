#!/usr/bin/env bash
# scripts/cache-canary.sh — P0-2 §12 缓存灰度：放量门禁校验 + 证据 + 回滚指引（G3）。
#
# 用法:
#   CACHE_METRICS_URL=http://127.0.0.1:18080/metrics bash scripts/cache-canary.sh --stage G-2
#   bash scripts/cache-canary.sh --rollback --to G-1
#
# 退出码：0 门禁通过（MANUAL/待环境项不视为失败）；1 门禁未过；2 参数/初始化错误。
#
# 偏差登记（重要）：灰度配置**下发热更新（§6.10）尚未接线**，故本脚本**不执行配置下发**——
#   只做「门禁校验 + 证据 JSON + 回滚动作指引」；放量/回滚的配置变更按当前机制走
#   「配置文件（CACHE_CONFIG_PATH）+ 滚动重启」，由外部运维执行。
set -uo pipefail

CACHE_METRICS_URL="${CACHE_METRICS_URL:-}"
CACHE_CANARY_OUT="${CACHE_CANARY_OUT:-deploy/cache-canary-runs}"
# 延迟预算（§8.1：精确查表进程内 p95 < 1ms）
EXACT_P95_BUDGET_MS="${EXACT_P95_BUDGET_MS:-1}"

STAGE=""
ROLLBACK=0
TO_STAGE=""

usage() {
  cat >&2 <<'EOF'
用法：
  cache-canary.sh --stage <G-0..G-5>      # 校验该阶段门禁（§12.2），产出证据 JSON
  cache-canary.sh --rollback [--to <G-N>] # 输出回滚动作指引（§12.3），产出证据 JSON
环境变量：
  CACHE_METRICS_URL   tee-infer /metrics 地址（--stage 必填）
  CACHE_CANARY_OUT    证据输出目录（默认 deploy/cache-canary-runs）
  EXACT_P95_BUDGET_MS 精确查表 p95 预算（默认 1ms，§8.1）
EOF
  exit 2
}

valid_stage() { case "$1" in G-0|G-1|G-2|G-3|G-4|G-5) return 0 ;; *) return 1 ;; esac; }
prev_stage() {
  case "$1" in G-0) echo "" ;; G-1) echo "G-0" ;; G-2) echo "G-1" ;;
    G-3) echo "G-2" ;; G-4) echo "G-3" ;; G-5) echo "G-4" ;; *) echo "" ;; esac
}

while [ $# -gt 0 ]; do
  case "$1" in
    --stage) STAGE="${2:-}"; shift 2 ;;
    --rollback) ROLLBACK=1; shift ;;
    --to) TO_STAGE="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "未知参数: $1" >&2; usage ;;
  esac
done

if [ "$ROLLBACK" -eq 0 ] && [ -z "$STAGE" ]; then usage; fi
if [ -n "$STAGE" ] && ! valid_stage "$STAGE"; then echo "非法阶段: $STAGE" >&2; exit 2; fi
if [ -n "$TO_STAGE" ] && ! valid_stage "$TO_STAGE"; then echo "--to 非法阶段: $TO_STAGE" >&2; exit 2; fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_TS="$(date +%Y-%m-%dT%H-%M-%S)"
EVIDENCE_DIR="$CACHE_CANARY_OUT/evidence/$RUN_TS"
mkdir -p "$EVIDENCE_DIR"
CHECKS_FILE="$(mktemp)"
trap 'rm -f "$CHECKS_FILE"' EXIT

json_escape() {
  local s="${1//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

# add_check id name target actual result(PASS|FAIL|MANUAL)
add_check() {
  printf '{"id":"%s","name":"%s","target":"%s","actual":"%s","result":"%s"}\n' \
    "$1" "$(json_escape "$2")" "$(json_escape "$3")" "$(json_escape "$4")" "$5" >>"$CHECKS_FILE"
}

# ---- 指标解析（Prometheus 文本） ----
# mval "<完整指标名含标签>" → 数值（缺失 = 0）
# 容忍行首 BOM/空白（容错 <=3 字节前缀），正常 /metrics 为前缀 1 匹配。
mval() {
  awk -v k="$1" '
    { p=index($0,k); if (p==1 || (p>1 && p<=4)) v=$2 }
    END { printf "%d", v+0 }' "$METRICS_FILE"
}

# p95_ms <kind> → p95（毫秒，整数）；无样本 = -1
p95_ms() {
  awk -v kind="$1" '
    $1 ~ /^otpmask_cache_lookup_duration_seconds_bucket\{/ && index($1, "kind=\"" kind "\"") > 0 {
      le=""; if (match($1, /le="[^"]+"/)) { le=substr($1, RSTART+4, RLENGTH-5) }
      v=$2+0
      if (le=="+Inf") { inf=v } else { n++; b[n]=le+0; c[n]=v }
    }
    END {
      if (!inf) { print -1; exit }
      target=inf*0.95
      for (i=1;i<=n;i++) { if (c[i] >= target) { printf "%d", b[i]*1000; exit } }
      print 999999
    }' "$METRICS_FILE"
}

# 精确命中率（M1，% ×100 整数口径）；用 bash 计算
hit_rate_pct() {
  local hit miss fc denom
  hit="$(mval 'otpmask_cache_lookups_total{kind="exact",result="hit"}')"
  miss="$(mval 'otpmask_cache_lookups_total{kind="exact",result="miss"}')"
  fc="$(mval 'otpmask_cache_lookups_total{kind="exact",result="fastcheck_miss"}')"
  denom=$((hit + miss + fc))
  if [ "$denom" -eq 0 ]; then echo "-1"; return; fi
  # 百分比 ×100（如 1530 = 15.30%）
  echo $((hit * 10000 / denom))
}

# 语义误命中率（M5，% ×100）；无语义命中 = -1（不判）
sem_fp_rate_pct() {
  local hit fp
  hit="$(mval 'otpmask_cache_lookups_total{kind="semantic",result="hit"}')"
  fp="$(mval 'otpmask_cache_semantic_false_positive_total')"
  if [ "$hit" -eq 0 ]; then echo "-1"; return; fi
  echo $((fp * 10000 / hit))
}

fetch_metrics() {
  if [ -z "$CACHE_METRICS_URL" ]; then
    echo "CACHE_METRICS_URL 未设置（--stage 必填）" >&2
    exit 2
  fi
  METRICS_FILE="$(mktemp)"
  if ! curl -fsS --max-time 5 "$CACHE_METRICS_URL" >"$METRICS_FILE" 2>/dev/null; then
    echo "metrics 不可达: $CACHE_METRICS_URL" >&2
    exit 2
  fi
}

# gate_hit_rate <stage> <min_pct_x100>
gate_hit_rate() {
  local r; r="$(hit_rate_pct)"
  if [ "$r" -lt 0 ]; then add_check "M1" "精确命中率" ">$2/100%" "无样本" "MANUAL"; return 0; fi
  if [ "$r" -gt "$2" ]; then add_check "M1" "精确命中率" ">$2/100%" "$r/100%" "PASS"; else
    add_check "M1" "精确命中率" ">$2/100%" "$r/100%" "FAIL"; fi
}

gate_latency() {
  local p; p="$(p95_ms exact)"
  if [ "$p" -lt 0 ]; then add_check "M3" "精确查表 p95" "<${EXACT_P95_BUDGET_MS}ms" "无样本" "MANUAL"; return 0; fi
  if [ "$p" -le "$EXACT_P95_BUDGET_MS" ]; then add_check "M3" "精确查表 p95" "<${EXACT_P95_BUDGET_MS}ms" "${p}ms" "PASS"; else
    add_check "M3" "精确查表 p95" "<${EXACT_P95_BUDGET_MS}ms" "${p}ms" "FAIL"; fi
}

gate_sem_fp() {
  local r; r="$(sem_fp_rate_pct)"
  if [ "$r" -lt 0 ]; then add_check "M5" "语义误命中率" "<100/100%" "无语义命中（不判）" "MANUAL"; return 0; fi
  if [ "$r" -lt 100 ]; then add_check "M5" "语义误命中率" "<100/100%" "$r/100%" "PASS"; else
    add_check "M5" "语义误命中率" "<100/100%" "$r/100%" "FAIL"; fi
}

# 各阶段门禁（§12.2）
run_stage_gates() {
  case "$1" in
    G-0)
      add_check "W-1" "写入成功率" ">99%" "MANUAL（无 stores 计数器，待补指标）" "MANUAL"
      add_check "W-2" "无误命中" "0" "MANUAL（告警系统核对）" "MANUAL"
      ;;
    G-1) gate_hit_rate G-1 1000 ;;
    G-2) gate_hit_rate G-2 1500; gate_latency ;;
    G-3) add_check "A-1" "无 P1 告警" "0" "MANUAL（需告警系统）" "MANUAL" ;;
    G-4) gate_sem_fp ;;
    G-5) add_check "A-2" "无 P1 告警" "0" "MANUAL（需告警系统）" "MANUAL" ;;
  esac
}

emit_evidence() {
  local overall="$1" kind="$2" extra="$3"
  local checks; checks="$(awk 'BEGIN{f=1}{if(!f)printf ",";printf "%s",$0;f=0}' "$CHECKS_FILE")"
  local out="$EVIDENCE_DIR/cache-canary.json"
  printf '{"script":"cache-canary","kind":"%s","ts":"%s","metrics_url":"%s","stage":"%s","to_stage":"%s","overall":"%s"%s,"checks":[%s]}\n' \
    "$kind" "$(date +%Y-%m-%dT%H:%M:%S%z)" "$(json_escape "$CACHE_METRICS_URL")" "$STAGE" "$TO_STAGE" "$overall" "$extra" "$checks" >"$out"
  echo "证据: $out"
}

# ===== 主流程 =====
if [ "$ROLLBACK" -eq 1 ]; then
  if [ -z "$TO_STAGE" ]; then
    echo "回滚需 --to <G-N>（目标阶段）" >&2
    exit 2
  fi
  add_check "R-1" "写回 gray.stage" "$TO_STAGE" "配置文件 CACHE_CONFIG_PATH（外部执行）" "MANUAL"
  add_check "R-2" "滚动重启 tee-infer" "生效" "热更新未接线，需重启（外部执行）" "MANUAL"
  add_check "R-3" "校验 canary_total{stage=$TO_STAGE}" ">0" "重启后核对 /metrics" "MANUAL"
  add_check "R-4" "误命中率/告警回落" "达标" "按 §12.2 回滚判据人工核对" "MANUAL"
  emit_evidence "MANUAL" "rollback" ",\"rollback_directive\":\"写回 gray.stage=$TO_STAGE + 滚动重启\""
  echo "回滚指引已产出（按当前机制：配置写回 + 滚动重启；热更新接线后可自动化）"
  exit 0
fi

fetch_metrics
run_stage_gates "$STAGE"

overall="PASS"
if grep -q '"result":"FAIL"' "$CHECKS_FILE"; then overall="FAIL"; fi
manual="$(grep -c '"result":"MANUAL"' "$CHECKS_FILE" || true)"
emit_evidence "$overall" "stage" ",\"manual_checks\":$manual"

echo "阶段 $STAGE 门禁：$overall（MANUAL=$manual）"
if [ "$overall" = "FAIL" ]; then exit 1; fi
exit 0
