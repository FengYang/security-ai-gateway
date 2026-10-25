#!/usr/bin/env bash
# scripts/drills/d1-data-plane-failure.sh — P2-4 T-6.1 演练矩阵 ①：单集群数据面故障。
#
# 场景：向集群 A 的数据面（gateway-core）注入故障，验证
#   · 集群 B 不受影响（故障隔离，R-4 打标维度不混淆）
#   · 集群 A 数据面**自治**（R-1：拉取缓存保留旧策略，策略照旧生效，不做 fail-open 放行）
#   · 故障清除后 A 恢复并重新收敛
#
# 注入环境变量（演练环境）：
#   FAULT_INJECT_CMD   对 A 注入数据面故障（脚本注入 CLUSTER_ID）
#   FAULT_CLEAR_CMD    清除 A 的故障（脚本注入 CLUSTER_ID）
#   HEALTH_URL_A/B     两集群健康源（也可用 HEALTH_URL_<CLUSTER 大写>）
#   ROUTES_PROBE_CMD   A 的本地策略拉取探针（脚本注入 CLUSTER_ID）；用于验证"保留旧策略"
#   OBSERVE_CMD        业务观测钩子（可选）
#
# 退出码：0 通过｜1 失败｜2 参数错误｜3 环境前置不满足（本机无双集群环境时明确报错，不伪称通过）。

set -uo pipefail

_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$_SELF_DIR/_lib.sh"

TARGET_CLUSTER="cluster-a"
PEER_CLUSTER="cluster-b"

while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET_CLUSTER="${2:-}"; shift 2 ;;
    --peer) PEER_CLUSTER="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --out) DRILL_OUT="${2:-}"; shift 2 ;;
    --out=*) DRILL_OUT="${1#*=}"; shift ;;
    -h|--help)
      printf '用法：d1-data-plane-failure.sh [--target cluster-a] [--peer cluster-b] [--dry-run] [--out DIR]\n'
      exit 0 ;;
    *) echo "未知参数：$1" >&2; exit "$DR_EXIT_ARGS" ;;
  esac
done

DRILL_ID="d1-data-plane-failure"
DRILL_TITLE="单集群数据面故障（目标 $TARGET_CLUSTER，对照 $PEER_CLUSTER）"
dr_init

health_url_of() {
  # HEALTH_URL_<CLUSTER 大写、下划线化> → HEALTH_URL（全局）。
  # 注：集群 id 含 '-' 不可直接做变量名，故统一下划线化（${HEALTH_URL_cluster-a:-} 会被 bash 误解析）。
  local cid="$1" key
  key="$(printf '%s' "$cid" | tr '[:lower:]-' '[:upper:]_')"
  local v1="HEALTH_URL_${key}" v3="HEALTH_URL"
  eval "local a=\"\${$v1:-}\"; local c=\"\${$v3:-}\""
  if [ -n "$a" ]; then printf '%s' "$a"; return 0; fi
  if [ -n "$c" ]; then printf '%s' "$c"; return 0; fi
  return 1
}

# ---------- 阶段 1：预检 ----------
dr_step "1-precheck" "预检" pass "开始"
if ! dr_require_env "故障注入钩子" FAULT_INJECT_CMD; then
  dr_write_report; dr_write_evidence_md "- 故障注入方式（kubectl / 网络策略 / 节点隔离）：TODO(人工)"; exit "$DR_EXIT_ENV"
fi
if ! dr_require_env "故障清除钩子" FAULT_CLEAR_CMD; then
  dr_write_report; dr_write_evidence_md "- 故障清除方式：TODO(人工)"; exit "$DR_EXIT_ENV"
fi
url_t="$(health_url_of "$TARGET_CLUSTER")" || url_t=""
url_p="$(health_url_of "$PEER_CLUSTER")" || url_p=""
if [ -z "$url_t" ] || [ -z "$url_p" ]; then
  dr_step "env" "双集群健康源" env_unmet "缺少 HEALTH_URL（需 $TARGET_CLUSTER 与 $PEER_CLUSTER 各一）"
  DR_ENV_UNMET=1
  dr_write_report; dr_write_evidence_md "- 双集群地址：TODO(人工)"; exit "$DR_EXIT_ENV"
fi
code_t="$(dr_http_code "$url_t")"; code_p="$(dr_http_code "$url_p")"
case "$code_t$code_p" in
  2??2??) dr_pass "1.1-health" "双集群基线健康" "target=$code_t peer=$code_p" ;;
  *)
    dr_fail "1.1-health" "双集群基线健康" "target=$code_t peer=$code_p（基线不健康，演练前提不成立）"
    dr_write_report; exit "$DR_EXIT_FAIL" ;;
esac
if [ -n "${ROUTES_PROBE_CMD:-}" ]; then
  export CLUSTER_ID="$TARGET_CLUSTER"
  before="$(bash -c "$ROUTES_PROBE_CMD" 2>&1)"; rc=$?
  if [ $rc -eq 0 ]; then
    dr_pass "1.2-probe" "故障前策略快照" "$before"
    printf '%s' "$before" > "$DR_EVIDENCE_DIR/routes-before.txt"
  else
    dr_fail "1.2-probe" "故障前策略快照" "exit $rc：$before"
  fi
else
  dr_skip "1.2-probe" "故障前策略快照" "未注入 ROUTES_PROBE_CMD（自治验证将无法取证，记 skip）"
fi
dr_step "1-precheck" "预检" pass "预检完成"

# ---------- 阶段 2：执行（注入故障）----------
export CLUSTER_ID="$TARGET_CLUSTER"
dr_exec "2-inject" "注入数据面故障（$TARGET_CLUSTER）" "$FAULT_INJECT_CMD"

# ---------- 阶段 3：观测 ----------
code_t2="$(dr_http_code "$url_t")"
if dr_dryrun_dependent "3.1-target-down" "目标集群不可用" "须在故障注入后成立（HTTP 000/5xx）；dry-run 未注入故障故不断言"; then
  :
else
  case "$code_t2" in
    000 | 5*) dr_pass "3.1-target-down" "目标集群不可用" "HTTP $code_t2（故障已生效）" ;;
    *) dr_fail "3.1-target-down" "目标集群不可用" "HTTP $code_t2（故障未按预期生效）" ;;
  esac
fi
code_p2="$(dr_http_code "$url_p")"
case "$code_p2" in
  2??) dr_pass "3.2-peer-ok" "对照集群不受影响" "HTTP $code_p2（故障隔离，R-4）" ;;
  *) dr_fail "3.2-peer-ok" "对照集群不受影响" "HTTP $code_p2（故障扩散！须中止并复盘）" ;;
esac
# 自治验证：目标集群的策略拉取应"失败但保留旧策略"（R-1）⇒ 探针应报"仍旧策略"而非"无策略"
if dr_dryrun_dependent "3.3-autonomy" "数据面自治（R-1：保留旧策略）" "须在故障注入后成立；dry-run 不断言"; then
  :
elif [ -n "${ROUTES_PROBE_CMD:-}" ]; then
  export CLUSTER_ID="$TARGET_CLUSTER"
  during="$(bash -c "$ROUTES_PROBE_CMD" 2>&1)"; rc=$?
  printf '%s' "$during" > "$DR_EVIDENCE_DIR/routes-during.txt"
  if [ $rc -eq 0 ]; then
    dr_pass "3.3-autonomy" "数据面自治（R-1：保留旧策略）" "$during"
  else
    dr_fail "3.3-autonomy" "数据面自治（R-1：保留旧策略）" "探针失败 exit $rc：$during（须为'拉取失败但旧策略仍在'，而非策略清空）"
  fi
else
  dr_skip "3.3-autonomy" "数据面自治（R-1）" "未注入 ROUTES_PROBE_CMD"
fi
if [ -n "${OBSERVE_CMD:-}" ]; then
  export CLUSTER_ID="$PEER_CLUSTER"; export WINDOW_SEC="30"
  dr_exec_ro "3.4-observe" "业务观测（对照集群）" "$OBSERVE_CMD"
else
  dr_skip "3.4-observe" "业务观测" "未注入 OBSERVE_CMD"
fi

# ---------- 阶段 4：确认（人工）----------
if ! dr_confirm_gate "确认故障影响面符合预期（$TARGET_CLUSTER 不可用、$PEER_CLUSTER 正常、旧策略保留）？"; then
  dr_write_report
  dr_write_evidence_md "- 影响面判定：TODO(人工)"; exit "$DR_EXIT_FAIL"
fi

# ---------- 阶段 5：记录（含故障恢复）----------
export CLUSTER_ID="$TARGET_CLUSTER"
dr_exec "5-clear" "清除故障（$TARGET_CLUSTER）" "$FAULT_CLEAR_CMD"
code_t3="$(dr_http_code "$url_t")"
if dr_dryrun_dependent "5.1-recover" "目标集群恢复" "须在故障清除后成立；dry-run 未清除故障故不断言"; then
  :
else
  case "$code_t3" in
    2??) dr_pass "5.1-recover" "目标集群恢复" "HTTP $code_t3" ;;
    *) dr_fail "5.1-recover" "目标集群恢复" "HTTP $code_t3（未恢复）" ;;
  esac
fi
if [ -n "${ROUTES_PROBE_CMD:-}" ]; then
  export CLUSTER_ID="$TARGET_CLUSTER"
  after="$(bash -c "$ROUTES_PROBE_CMD" 2>&1)"; rc=$?
  printf '%s' "$after" > "$DR_EVIDENCE_DIR/routes-after.txt"
  if [ $rc -eq 0 ]; then
    dr_pass "5.2-reconverge" "恢复后策略收敛" "$after"
  else
    dr_fail "5.2-reconverge" "恢复后策略收敛" "exit $rc：$after"
  fi
fi
dr_write_report
dr_write_evidence_md "- 故障注入与恢复时间点：TODO(人工)
- 目标集群自治证据（拉取失败但旧策略生效）：TODO(人工)复核 routes-during.txt
- 业务影响面与时长：TODO(人工)"
printf '报告：%s\n' "$DR_EVIDENCE_DIR/report.json"
# 退出码由主流程一处决定（★ EXIT trap 只做收尾写报告，不改变已决定的退出状态）。
dr_compute_exit_code $?
exit "$DR_FINAL_CODE"
