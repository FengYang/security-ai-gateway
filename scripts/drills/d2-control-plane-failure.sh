#!/usr/bin/env bash
# scripts/drills/d2-control-plane-failure.sh — P2-4 T-6.1 演练矩阵 ②：控制面故障（R-1 自治验证）。
#
# 场景：使**管理面**（gateway-admin-service / 中央组件）不可达，验证
#   · 各集群数据面照常运行（R-1 单集群自治：拉取缓存 + 失败保留旧策略）
#   · 数据面**不引入新的集中单点**（R-1 后半句）
#   · 策略拉取失败时**保留旧策略**（不得 fail-open 放行；R-2 fail-closed 不弱化）
#   · 审计链不中断（各集群本地链独立，R-5）
#   · 管理面恢复后重新收敛
#
# 注入环境变量（演练环境）：
#   CONTROL_FAULT_CMD  使管理面不可达（脚本注入 TARGET）
#   CONTROL_CLEAR_CMD  恢复管理面（脚本注入 TARGET）
#   ADMIN_URL          管理面基址（用于恢复后的可达性验证）
#   HEALTH_URL         数据面/网关健康源
#   PLUGIN_PULL_CMD    插件拉取探针（脚本注入 CLUSTER_ID）；应观察到"拉取失败但旧策略保留"
#   AUDIT_VERIFY_CMD   审计链校验探针（脚本注入 CLUSTER_ID）；应观察到各集群链仍完好
#   OBSERVE_CMD        业务观测钩子（可选）
#
# 退出码：0 通过｜1 失败｜2 参数错误｜3 环境前置不满足。

set -uo pipefail

_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$_SELF_DIR/_lib.sh"

TARGET="admin"

while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --out) DRILL_OUT="${2:-}"; shift 2 ;;
    --out=*) DRILL_OUT="${1#*=}"; shift ;;
    -h|--help)
      printf '用法：d2-control-plane-failure.sh [--target admin] [--dry-run] [--out DIR]\n'
      exit 0 ;;
    *) echo "未知参数：$1" >&2; exit "$DR_EXIT_ARGS" ;;
  esac
done

DRILL_ID="d2-control-plane-failure"
DRILL_TITLE="控制面故障（$TARGET 不可达，R-1 自治验证）"
dr_init

# ---------- 阶段 1：预检 ----------
dr_step "1-precheck" "预检" pass "开始"
if ! dr_require_env "控制面故障注入钩子" CONTROL_FAULT_CMD; then
  dr_write_report; dr_write_evidence_md "- 控制面故障注入方式（网络策略/证书吊销/摘流）：TODO(人工)"; exit "$DR_EXIT_ENV"
fi
if ! dr_require_env "控制面恢复钩子" CONTROL_CLEAR_CMD; then
  dr_write_report; dr_write_evidence_md "- 控制面恢复方式：TODO(人工)"; exit "$DR_EXIT_ENV"
fi
if [ -z "${HEALTH_URL:-}" ]; then
  dr_step "env" "数据面健康源" env_unmet "缺少 HEALTH_URL"
  DR_ENV_UNMET=1
  dr_write_report; dr_write_evidence_md "- 数据面健康源：TODO(人工)"; exit "$DR_EXIT_ENV"
fi
code="$(dr_http_code "$HEALTH_URL")"
case "$code" in
  2??) dr_pass "1.1-health" "数据面基线健康" "HTTP $code $HEALTH_URL" ;;
  *)
    dr_fail "1.1-health" "数据面基线健康" "HTTP $code（基线不健康，演练前提不成立）"
    dr_write_report; exit "$DR_EXIT_FAIL" ;;
esac
if [ -n "${ADMIN_URL:-}" ]; then
  acode="$(dr_http_code "$ADMIN_URL")"
  case "$acode" in
    2?? | 3?? | 401 | 403) dr_pass "1.2-admin" "管理面基线可达" "HTTP $acode $ADMIN_URL" ;;
    *)
      dr_fail "1.2-admin" "管理面基线可达" "HTTP $acode $ADMIN_URL"
      dr_write_report; exit "$DR_EXIT_FAIL" ;;
  esac
else
  dr_skip "1.2-admin" "管理面基线可达" "未配置 ADMIN_URL"
fi
dr_step "1-precheck" "预检" pass "预检完成"

# ---------- 阶段 2：执行（控制面不可达）----------
export TARGET
dr_exec "2-fault" "使管理面不可达" "$CONTROL_FAULT_CMD"

# ---------- 阶段 3：观测（自治）----------
code2="$(dr_http_code "$HEALTH_URL")"
case "$code2" in
  2??) dr_pass "3.1-dataplane-alive" "数据面照常运行（R-1）" "HTTP $code2 $HEALTH_URL" ;;
  *) dr_fail "3.1-dataplane-alive" "数据面照常运行（R-1）" "HTTP $code2（数据面随管理面一起不可用 ⇒ 违反 R-1 集中单点）" ;;
esac
if dr_dryrun_dependent "3.2-keep-old" "拉取失败但保留旧策略（R-1/R-2）" "须在控制面不可达后成立；dry-run 不断言"; then
  :
elif [ -n "${PLUGIN_PULL_CMD:-}" ]; then
  export CLUSTER_ID="${PROBE_CLUSTER:-cluster-a}"
  pull="$(bash -c "$PLUGIN_PULL_CMD" 2>&1)"; rc=$?
  printf '%s' "$pull" > "$DR_EVIDENCE_DIR/plugin-pull-during.txt"
  if [ $rc -ne 0 ] && printf '%s' "$pull" | grep -qiE "保留|旧策略|keep|stale|cache"; then
    dr_pass "3.2-keep-old" "拉取失败但保留旧策略（R-1/R-2）" "$pull"
  elif [ $rc -eq 0 ]; then
    dr_fail "3.2-keep-old" "拉取失败但保留旧策略（R-1/R-2）" "拉取竟然成功：$pull（管理面应不可达）"
  else
    dr_fail "3.2-keep-old" "拉取失败但保留旧策略（R-1/R-2）" "探针未体现'保留旧策略'语义：$pull"
  fi
else
  dr_skip "3.2-keep-old" "拉取失败但保留旧策略" "未注入 PLUGIN_PULL_CMD"
fi
if [ -n "${AUDIT_VERIFY_CMD:-}" ]; then
  export CLUSTER_ID="${PROBE_CLUSTER:-cluster-a}"
  av="$(bash -c "$AUDIT_VERIFY_CMD" 2>&1)"; rc=$?
  if [ $rc -eq 0 ]; then
    dr_pass "3.3-audit-intact" "审计链未因控制面故障中断（R-5）" "$av"
  else
    dr_fail "3.3-audit-intact" "审计链未因控制面故障中断（R-5）" "exit $rc：$av"
  fi
else
  dr_skip "3.3-audit-intact" "审计链完整性" "未注入 AUDIT_VERIFY_CMD"
fi
if [ -n "${OBSERVE_CMD:-}" ]; then
  export WINDOW_SEC="30"; dr_exec_ro "3.4-observe" "业务观测" "$OBSERVE_CMD"
else
  dr_skip "3.4-observe" "业务观测" "未注入 OBSERVE_CMD"
fi

# ---------- 阶段 4：确认 ----------
if ! dr_confirm_gate "确认控制面不可达期间数据面自治行为符合 R-1（业务不中断、策略不失效）？"; then
  dr_write_report
  dr_write_evidence_md "- 自治判定：TODO(人工)"; exit "$DR_EXIT_FAIL"
fi

# ---------- 阶段 5：记录（恢复 + 收敛）----------
export TARGET
dr_exec "5-clear" "恢复管理面" "$CONTROL_CLEAR_CMD"
if [ -n "${ADMIN_URL:-}" ]; then
  acode2="$(dr_http_code "$ADMIN_URL")"
  if dr_dryrun_dependent "5.1-admin-back" "管理面恢复可达" "须在恢复管理面后成立；dry-run 未恢复故不断言"; then
    :
  else
    case "$acode2" in
      2?? | 3?? | 401 | 403) dr_pass "5.1-admin-back" "管理面恢复可达" "HTTP $acode2" ;;
      *) dr_fail "5.1-admin-back" "管理面恢复可达" "HTTP $acode2" ;;
    esac
  fi
fi
if [ -n "${PLUGIN_PULL_CMD:-}" ]; then
  export CLUSTER_ID="${PROBE_CLUSTER:-cluster-a}"
  pull2="$(bash -c "$PLUGIN_PULL_CMD" 2>&1)"; rc=$?
  if [ $rc -eq 0 ]; then
    dr_pass "5.2-reconverge" "恢复后拉取成功并收敛" "$pull2"
  else
    dr_fail "5.2-reconverge" "恢复后拉取成功并收敛" "exit $rc：$pull2"
  fi
fi
dr_write_report
dr_write_evidence_md "- 控制面不可达时长：TODO(人工)
- 自治期间业务影响（请求成功率/延迟）：TODO(人工)
- 是否出现数据面集中单点：TODO(人工)复核部署拓扑"
printf '报告：%s\n' "$DR_EVIDENCE_DIR/report.json"
# 退出码由主流程一处决定（★ EXIT trap 只做收尾写报告，不改变已决定的退出状态）。
dr_compute_exit_code $?
exit "$DR_FINAL_CODE"
