#!/usr/bin/env bash
# tracing-verify.sh — P1-2 全链路 tracing 实测验证 harness（V-3 性能 / V-7 采样 / V-9 灰度与回滚）
#
# 定位：把 P1-2 本体（《GA-AI网关能力补齐方案--P1--全链路tracing.md》）§1.4 与 §9.1 的
#      「实测留证」口径固化为**可执行验证体**。本脚本**只采集原始数据，不产出结论**；
#      结论由执行人按判据判定后回填《...-全链路tracing-验证与留证记录.md》。
#
# 三段（对应判据）：
#   v3 —— 性能基线（V-3/C-6）：同压测条件下 p99(开) ≤ 1.05 × p99(关)
#         口径：边缘全量插桩（根采样 100%、span 全量导出）、Collector tail_sampling 落存 1%；
#         测量点＝网关端到端总延迟；并发/时长/请求体必须固定并随报告留证。
#   v7 —— 采样可配置（V-7）：租户 allow-list 增/删生效（事实源＝Collector ConfigMap，
#         deny-by-default）；POST 返回 200 即代表已生效（fail-closed：任一步失败 → 503）。
#   v9 —— 灰度与回滚（V-9）：按租户灰度开启后该租户请求**可见 trace**；关闭/一键关闭后**不可见**。
#
# 前置：
#   - 环境已部署且可达：数据面（GATEWAY_URL）、管理面（ADMIN_URL，需 ADMIN_TEMPO_URL 已配置）、
#     Collector、Tempo、Prometheus。
#   - 具备 `system_admin` 且 **MFA 新鲜**的会话令牌（写端点 `POST /tracing/tenant` 要求 step-up）。
#   - 压测工具 `wrk` 或 `ab` 之一；`curl`、`python` 可用。
#
# 用法（三段可单独执行；`all` 顺序执行 v3(off)→v3(on)→v7→v9）：
#   GATEWAY_URL=http://127.0.0.1:10000 \
#   ADMIN_URL=http://127.0.0.1:8080 \
#   ADMIN_TOKEN=<system_admin+MFA 令牌> \
#   TENANT=<灰度租户> \
#   PAYLOAD=./probe.json \
#   DURATION=30s CONC=16 OUT_DIR=docs/benchmark/tracing \
#   ./scripts/tracing-verify.sh v3 --state off
#
#   ./scripts/tracing-verify.sh v7
#   ./scripts/tracing-verify.sh v9 --phase on     # 灰度开启态探针 + 可见性断言
#   ./scripts/tracing-verify.sh v9 --phase off    # 关闭/一键关闭后探针 + 不可见断言
#
# 说明（不臆断）：
#   - 全局开关/一键关闭 = `TRACING_ENABLED`（各服务环境变量）+ 滚动重启；**本脚本不改集群**，
#     仅打印待执行的 kubectl 命令，由运维按《接入与运维手册》§1 执行（避免脚本变更生产）。
#   - allow-list 生效有**秒级滚动重建时延**（手册 §1），v9 探针前会等待 `SETTLE_SEC`（默认 40s，
#     覆盖 Collector `decision_wait=30s`）；期间该实例短暂重启，tracing 非关键路径。
#   - Tempo 查询经管理面 `GET /v1/adminext/trace/search`（租户隔离生效、与面板同源），
#     不直连 Tempo，避免绕开权限与租户收敛。

set -uo pipefail   # 不用 -e：采集失败应如实记录并继续，而非中途退出

# ---------------- 参数解析 ----------------
case "${1:-}" in
  -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
esac
SUB="${1:-all}"; shift || true
STATE=""; PHASE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --state) STATE="${2:-}"; shift 2 ;;
    --phase) PHASE="${2:-}"; shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:10000}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:8080}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"
TENANT="${TENANT:-}"
PAYLOAD="${PAYLOAD:-}"
DURATION="${DURATION:-30s}"
CONC="${CONC:-16}"
SETTLE_SEC="${SETTLE_SEC:-40}"
OUT_DIR="${OUT_DIR:-docs/benchmark/tracing}"
WRK_SCRIPT="${WRK_SCRIPT:-}"

[ -n "$ADMIN_TOKEN" ] || { echo "ERROR: ADMIN_TOKEN 必填（system_admin + MFA 新鲜令牌）" >&2; exit 2; }
mkdir -p "$OUT_DIR"

have() { command -v "$1" >/dev/null 2>&1; }
die()  { echo "ERROR: $*" >&2; exit 2; }

# admin 调用：$1=method $2=path [$3=json body]
admin() {
  local m="$1" p="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sS -X "$m" "${ADMIN_URL}${p}" -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      -H 'Content-Type: application/json' -w '\n%{http_code}' -d "$body"
  else
    curl -sS -X "$m" "${ADMIN_URL}${p}" -H "Authorization: Bearer ${ADMIN_TOKEN}" -w '\n%{http_code}'
  fi
}
# 提取响应体（去掉末尾状态码行）与状态码
split_code() { printf '%s' "$1" | sed '$d'; }
last_code()  { printf '%s' "$1" | tail -n1; }
# JSON 取值（尽量不引入 jq）：python 一行
json_get() { printf '%s' "$1" | python -c "import sys,json;d=json.load(sys.stdin);print(d$2)" 2>/dev/null || echo ""; }

# ================= v3：性能基线（V-3） =================
run_v3() {
  [ -n "$STATE" ] || die "v3 需要 --state on|off（分别采集开启态/关闭态）"
  case "$STATE" in on|off) ;; *) die "--state 仅支持 on|off" ;; esac
  have wrk || have ab || die "需要 wrk 或 ab 之一"
  [ -n "$PAYLOAD" ] || die "v3 需要 PAYLOAD（压测请求体文件，固定场景）"

  local tool csv raw RPS P50 P99 requests
  have wrk && tool=wrk || tool=ab
  csv="${OUT_DIR}/v3-${STATE}.csv"; raw="${OUT_DIR}/v3-${STATE}.raw.txt"
  echo "== v3 性能基线：state=${STATE} tool=${tool} conc=${CONC} duration=${DURATION} =="

  if [ "$tool" = "wrk" ]; then
    if [ -n "$WRK_SCRIPT" ]; then
      wrk -t4 -c"$CONC" -d"$DURATION" --latency -s "$WRK_SCRIPT" "$GATEWAY_URL" >"$raw" 2>&1
    else
      wrk -t4 -c"$CONC" -d"$DURATION" --latency "$GATEWAY_URL" >"$raw" 2>&1
    fi
    RPS=$(grep -oE 'Requests/sec: *[0-9.]+' "$raw" | grep -oE '[0-9.]+' | head -1)
    P50=$(grep -E '^\s*50%\s' "$raw" | grep -oE '[0-9.]+[muni]*s?' | head -1)
    P99=$(grep -E '^\s*99%\s' "$raw" | grep -oE '[0-9.]+[muni]*s?' | head -1)
  else
    requests="${REQUESTS:-2000}"
    ab -n "$requests" -c"$CONC" -p "$PAYLOAD" -T 'application/json' "$GATEWAY_URL" >"$raw" 2>&1
    RPS=$(grep -oE 'Requests per second: *[0-9.]+' "$raw" | grep -oE '[0-9.]+' | head -1)
    P50=$(grep -E '^\s*50%' "$raw" | awk '{print $2}' | head -1)
    P99=$(grep -E '^\s*99%' "$raw" | awk '{print $2}' | head -1)
  fi
  printf 'state,tool,concurrency,duration,rps,p50,p99\n%s,%s,%s,%s,%s,%s,%s\n' \
    "$STATE" "$tool" "$CONC" "$DURATION" "${RPS:-NA}" "${P50:-NA}" "${P99:-NA}" >"$csv"
  echo "-- 采集完成：$csv"
  echo "   rps=${RPS:-NA} p50=${P50:-NA} p99=${P99:-NA}"

  if [ -f "${OUT_DIR}/v3-on.csv" ] && [ -f "${OUT_DIR}/v3-off.csv" ]; then
    local pon poff ratio
    pon=$(tail -n1 "${OUT_DIR}/v3-on.csv"  | awk -F, '{print $7}')
    poff=$(tail -n1 "${OUT_DIR}/v3-off.csv" | awk -F, '{print $7}')
    # 仅当两侧为纯数字（秒）时计算相对口径
    if printf '%s' "$pon"  | grep -qE '^[0-9.]+$' && printf '%s' "$poff" | grep -qE '^[0-9.]+$' && [ "${poff%.*}" != "0" ]; then
      ratio=$(python -c "print(round(float('$pon')/float('$poff'),4))")
      echo "== V-3 判定输入：p99(on)=${pon}s p99(off)=${poff}s 比值=${ratio}（判据 ≤ 1.05）=="
      python -c "print('V-3: PASS（<=1.05）' if float('$ratio')<=1.05 else 'V-3: FAIL（>1.05，需优化或按降级方案处置）')"
    else
      echo "== V-3：p99 非纯数字（wrk 单位如 ms），请人工换算后按 ≤1.05 判定（原始：on=${pon} off=${poff}）=="
    fi
  else
    echo "-- 提示：另一状态数据缺失，请切换状态后再跑一次本命令："
  fi
  echo "   切换 tracing 状态（运维执行，本脚本不改集群）："
  echo "     kubectl -n otpmask set env deployment/gateway-core deployment/gateway-admin-service deployment/tee-infer-service TRACING_ENABLED=$([ "$STATE" = on ] && echo false || echo true)"
  echo "     kubectl -n otpmask rollout status deployment/gateway-core --timeout=180s"
}

# ================= v7：采样可配置（V-7） =================
run_v7() {
  [ -n "$TENANT" ] || die "v7 需要 TENANT"
  local out="${OUT_DIR}/v7.json" resp body code tenants_on tenants_off
  echo "== v7 采样可配置（租户 allow-list，事实源=Collector ConfigMap，deny-by-default）=="

  # 1) 前置：tracing 是否已接线（未接线 → 写端点 503，属预期 fail-closed）
  resp=$(admin GET "/v1/adminext/slo?tenant=${TENANT}"); code=$(last_code "$resp"); body=$(split_code "$resp")
  echo "-- GET /slo -> $code（tracing_wired=$(json_get "$body" ".get('tracing_wired')") tracing_source=$(json_get "$body" ".get('tracing_source')")）"

  # 2) 开启租户灰度
  resp=$(admin POST "/v1/adminext/tracing/tenant" "{\"tenant\":\"${TENANT}\",\"enabled\":true}")
  code=$(last_code "$resp"); body=$(split_code "$resp")
  echo "-- POST enable tenant -> $code body=${body}"
  if [ "$code" != "200" ]; then
    echo "   [预期] 非 200：未接线/未过 MFA/审计链未启用 → 503；请按返回信息核对（fail-closed 正确行为）"
    echo "{\"tenant\":\"${TENANT}\",\"step\":\"enable\",\"http\":${code},\"body\":${body:-null}}" >"$out"
    return
  fi
  tenants_on=$(printf '%s' "$body" | python -c "import sys,json;print(','.join(json.load(sys.stdin).get('tenants',[])))" 2>/dev/null)
  echo "   allow-list(enable 后)=[${tenants_on}]"
  printf '%s' "$tenants_on" | grep -q "$TENANT" && echo "   [OK] 租户已在 allow-list" || echo "   [FAIL] 租户未进入 allow-list"

  # 3) 关闭租户灰度
  resp=$(admin POST "/v1/adminext/tracing/tenant" "{\"tenant\":\"${TENANT}\",\"enabled\":false}")
  code=$(last_code "$resp"); body=$(split_code "$resp")
  tenants_off=$(printf '%s' "$body" | python -c "import sys,json;print(','.join(json.load(sys.stdin).get('tenants',[])))" 2>/dev/null)
  echo "-- POST disable tenant -> $code allow-list(disable 后)=[${tenants_off}]"
  printf '%s' "$tenants_off" | grep -q "$TENANT" && echo "   [FAIL] 租户仍在 allow-list" || echo "   [OK] 租户已移出 allow-list（默认拒绝）"

  echo "{\"tenant\":\"${TENANT}\",\"enable_http\":200,\"after_enable\":\"${tenants_on}\",\"after_disable\":\"${tenants_off}\"}" >"$out"
  echo "-- 记录：$out"
}

# ================= v9：灰度与回滚（V-9） =================
run_v9() {
  [ -n "$TENANT" ] || die "v9 需要 TENANT"
  [ -n "$PAYLOAD" ] || die "v9 需要 PAYLOAD（探针请求体；须与 TENANT 对应的租户凭据/上下文一致）"
  case "$PHASE" in on|off) ;; *) die "v9 需要 --phase on|off" ;; esac
  local out="${OUT_DIR}/v9-${PHASE}.json" resp body code from to probe_code traces
  echo "== v9 灰度与回滚：phase=${PHASE} =="

  if [ "$PHASE" = "on" ]; then
    resp=$(admin POST "/v1/adminext/tracing/tenant" "{\"tenant\":\"${TENANT}\",\"enabled\":true}")
    echo "-- POST enable tenant -> $(last_code "$resp")"
  else
    resp=$(admin POST "/v1/adminext/tracing/tenant" "{\"tenant\":\"${TENANT}\",\"enabled\":false}")
    echo "-- POST disable tenant -> $(last_code "$resp")（一键关闭＝各服务 TRACING_ENABLED=false + 滚动重启，由运维执行）"
  fi

  echo "-- 等待 allow-list 生效（滚动重建）与 tail_sampling 决策窗：${SETTLE_SEC}s"
  sleep "$SETTLE_SEC"

  from=$(( $(date -u +%s) - 60 )); to=$(( $(date -u +%s) + 10 ))
  curl -sS -o /dev/null -w '' -X POST "$GATEWAY_URL" -H 'Content-Type: application/json' --data-binary @"$PAYLOAD" 2>/dev/null
  probe_code=$?
  resp=$(admin GET "/v1/adminext/trace/search?tenant=${TENANT}&from=${from}&to=${to}&limit=50")
  code=$(last_code "$resp"); body=$(split_code "$resp")
  traces=$(printf '%s' "$body" | python -c "import sys,json;d=json.load(sys.stdin);print(len(d.get('traces',[]) if isinstance(d,dict) else d))" 2>/dev/null)
  echo "-- 探针完成（curl rc=${probe_code}）；GET /trace/search -> $code，窗口 [${from},${to}] 命中 traces=${traces:-NA}"
  if [ "$PHASE" = "on" ]; then
    echo "   [判据] traces ≥ 1 → 灰度可见（V-9 开启态通过）"
  else
    echo "   [判据] traces = 0 → 关闭后不可见（V-9 回滚/一键关闭通过）"
  fi
  echo "{\"phase\":\"${PHASE}\",\"tenant\":\"${TENANT}\",\"from\":${from},\"to\":${to},\"probe_curl_rc\":${probe_code},\"search_http\":${code},\"traces\":\"${traces:-NA}\",\"body\":${body:-null}}" >"$out"
  echo "-- 记录：$out"
}

case "$SUB" in
  v3)  run_v3 ;;
  v7)  run_v7 ;;
  v9)  run_v9 ;;
  all)
    STATE=off run_v3
    STATE=on  run_v3
    run_v7
    PHASE=on  run_v9
    ;;
  *) echo "用法：$0 [v3 --state on|off | v7 | v9 --phase on|off | all]" >&2; exit 2 ;;
esac

echo "== 结束。原始数据已落 ${OUT_DIR}；结论请回填《...-全链路tracing-验证与留证记录.md》=="
