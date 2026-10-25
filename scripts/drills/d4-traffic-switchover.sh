#!/usr/bin/env bash
# scripts/drills/d4-traffic-switchover.sh — P2-4 T-6.1 演练矩阵 ④：切流/回切。
#
# 场景：以 T-5.2 的 traffic-shift.sh 为执行体，演练"主备切流 → 观测 → 回切"闭环，
# 对应验收 V-5：双集群主备切流演练，切换成功、业务影响窗口达 SOP 标称、回切可选。
#
# ★ 执行点在客户既有 DNS/GSLB/云 LB（D-5）：本脚本不实现调度器，
#   变更动作经 NB_SET_WEIGHT_CMD 等钩子注入；钩子缺失 ⇒ 退出码 3（环境不满足），不伪称通过。
#
# 注入环境变量：见 scripts/traffic-shift.sh 头注释（NB_SET_WEIGHT_CMD / NB_GET_WEIGHT_CMD /
#   HEALTH_URL_<cluster> / OBSERVE_CMD / PROM_URL / SWITCH_POLICY / CONFIRM / IMPACT_WINDOW_SEC / DNS_TTL_SEC）。
#
# 退出码：0 通过｜1 失败｜2 参数错误｜3 环境前置不满足。

set -uo pipefail

_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$_SELF_DIR/_lib.sh"

PRIMARY="cluster-a"
STANDBY="cluster-b"
SWITCH_SCRIPT="$_SELF_DIR/../traffic-shift.sh"

while [ $# -gt 0 ]; do
  case "$1" in
    --primary) PRIMARY="${2:-}"; shift 2 ;;
    --standby) STANDBY="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --out) DRILL_OUT="${2:-}"; shift 2 ;;
    --out=*) DRILL_OUT="${1#*=}"; shift ;;
    -h|--help)
      printf '用法：d4-traffic-switchover.sh [--primary cluster-a] [--standby cluster-b] [--dry-run] [--out DIR]\n'
      exit 0 ;;
    *) echo "未知参数：$1" >&2; exit "$DR_EXIT_ARGS" ;;
  esac
done

DRILL_ID="d4-traffic-switchover"
DRILL_TITLE="切流/回切（$PRIMARY → $STANDBY → 回切 $PRIMARY）"
dr_init

if [ ! -f "$SWITCH_SCRIPT" ]; then
  dr_fail "0-tooling" "执行体存在性" "找不到 $SWITCH_SCRIPT（T-5.2 脚本缺失）"
  dr_write_report; exit "$DR_EXIT_FAIL"
fi
dr_pass "0-tooling" "执行体存在性" "$SWITCH_SCRIPT"

# ---------- 阶段 1：预检（切流前置：standby 必须健康）----------
dr_step "1-precheck" "预检（回切目标健康）" pass "开始"
key="$(printf '%s' "$STANDBY" | tr '[:lower:]-' '[:upper:]_')"
standby_url=""
eval "standby_url=\"\${HEALTH_URL_${key}:-}\""
if [ -z "$standby_url" ]; then
  eval "standby_url=\"\${HEALTH_URL:-}\""
fi
if [ -z "$standby_url" ]; then
  dr_step "env" "回切目标健康源" env_unmet "缺少 HEALTH_URL（$STANDBY）"
  DR_ENV_UNMET=1
  dr_write_report; dr_write_evidence_md "- 回切目标地址：TODO(人工)"; exit "$DR_EXIT_ENV"
fi
code="$(dr_http_code "$standby_url")"
case "$code" in
  2??) dr_pass "1.1-standby-healthy" "回切目标健康" "HTTP $code $standby_url" ;;
  *)
    dr_fail "1.1-standby-healthy" "回切目标健康" "HTTP $code（目标不健康，禁止切流）"
    dr_write_report; exit "$DR_EXIT_FAIL" ;;
esac
dr_step "1-precheck" "预检" pass "预检完成"

# ---------- 阶段 2/3/4/5：委托 T-5.2 执行体完成切流五阶段 ----------
run_shift() {
  local action="$1" from="$2" to="$3"
  local args=(--action "$action" --from "$from" --to "$to" --out "$DR_EVIDENCE_DIR/$action")
  [ "$DRY_RUN" = "1" ] && args+=(--dry-run)
  bash "$SWITCH_SCRIPT" "${args[@]}" 2>&1
  return $?
}

dr_step "2-switch" "执行切流（$PRIMARY → $STANDBY）" pass "开始"
out="$(run_shift switch "$PRIMARY" "$STANDBY")"; rc=$?
printf '%s\n' "$out" | tee "$DR_EVIDENCE_DIR/switch.log"
case "$rc" in
  0) dr_pass "2-switch" "切流执行体" "exit 0（详见 switch.log）" ;;
  3) dr_step "2-switch" "切流执行体" env_unmet "exit 3：环境前置不满足（未真实切流）"; DR_ENV_UNMET=1 ;;
  *) dr_fail "2-switch" "切流执行体" "exit $rc：$out" ;;
esac

if [ "$rc" -eq 0 ]; then
  dr_step "3-failback" "执行回切（$STANDBY → $PRIMARY）" pass "开始"
  out2="$(run_shift failback "$PRIMARY" "$STANDBY")"; rc2=$?
  printf '%s\n' "$out2" | tee "$DR_EVIDENCE_DIR/failback.log"
  case "$rc2" in
    0) dr_pass "3-failback" "回切执行体" "exit 0（回切＝--action failback）" ;;
    3) dr_step "3-failback" "回切执行体" env_unmet "exit 3：环境前置不满足"; DR_ENV_UNMET=1 ;;
    *) dr_fail "3-failback" "回切执行体" "exit $rc2：$out2" ;;
  esac
else
  dr_blocked "3-failback" "回切（$STANDBY → $PRIMARY）" "切流未成功，未进入回切"
fi

# ---------- 阶段 4：确认 ----------
if [ "$rc" -eq 0 ]; then
  if ! dr_confirm_gate "确认切流与回切均已生效，业务恢复正常？"; then
    dr_write_report
    dr_write_evidence_md "- 切流/回切人工确认记录：TODO(人工)"; exit "$DR_EXIT_FAIL"
  fi
else
  dr_blocked "4-confirm" "人工确认" "切流未成功"
fi

# ---------- 阶段 5：记录 ----------
dr_write_report
dr_write_evidence_md "- 北向实际权重（切后/回切后）：TODO(人工)从客户 DNS/GSLB/云 LB 控制台核对
- 业务影响窗口实测（切流起→恢复）：TODO(人工)
- DNS TTL 与权重生效取大者的实际收敛时间：TODO(人工)
- 会话保持影响（长连接/流式）：TODO(人工)"
printf '报告：%s\n' "$DR_EVIDENCE_DIR/report.json"
# 退出码由主流程一处决定（★ EXIT trap 只做收尾写报告，不改变已决定的退出状态）。
dr_compute_exit_code $?
exit "$DR_FINAL_CODE"
