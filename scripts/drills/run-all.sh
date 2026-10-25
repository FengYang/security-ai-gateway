#!/usr/bin/env bash
# scripts/drills/run-all.sh — P2-4 T-6.1 演练矩阵编排（依次跑 5 个场景并汇总）。
#
# 矩阵（§7.2 T-6 ①）：
#   ① d1 单集群数据面故障     ② d2 控制面故障（R-1 自治）  ③ d3 存储主从切换
#   ④ d4 切流/回切            ⑤ d5 管理面跨机房 failover
#
# ★ 本机无双集群环境 ⇒ 默认**不**声称通过：任一场景环境前置不满足（退出码 3）
#   即整体判定 `env_unmet`，**不得**作为 V-6 验收证据。
#
# 退出码：0 全部通过｜1 存在失败场景｜2 参数错误｜3 存在环境不满足场景（待环境就绪）。
#
# 用法：scripts/drills/run-all.sh [--dry-run] [--out DIR] [--only d1,d4]

set -uo pipefail

_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$_SELF_DIR/_lib.sh"

ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --only) ONLY="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --out) DRILL_OUT="${2:-}"; shift 2 ;;
    --out=*) DRILL_OUT="${1#*=}"; shift ;;
    -h|--help)
      printf '用法：run-all.sh [--only d1,d4] [--dry-run] [--out DIR]\n'
      exit 0 ;;
    *) echo "未知参数：$1" >&2; exit "$DR_EXIT_ARGS" ;;
  esac
done

DRILL_ID="t6.1-drill-matrix"
DRILL_TITLE="P2-4 T-6.1 演练矩阵（5 场景）"
dr_init

SCENARIOS="d1-data-plane-failure d2-control-plane-failure d3-storage-failover d4-traffic-switchover d5-admin-geo-failover"

summary="$DR_EVIDENCE_DIR/matrix-summary.txt"
: > "$summary"

overall=0
env_unmet=0
for s in $SCENARIOS; do
  short="${s%%-*}"
  if [ -n "$ONLY" ]; then
    case ",$ONLY," in
      *",$short,"*) ;;
      *) continue ;;
    esac
  fi
  script="$_SELF_DIR/$s.sh"
  if [ ! -f "$script" ]; then
    dr_fail "matrix-$short" "场景 $s" "脚本缺失：$script"
    overall=1
    continue
  fi
  args=(--out "$DR_EVIDENCE_DIR/$s")
  [ "$DRY_RUN" = "1" ] && args+=(--dry-run)
  printf '\n===== 场景 %s（%s）=====\n' "$s" "$short"
  out="$(bash "$script" "${args[@]}" 2>&1)"
  rc=$?
  printf '%s\n' "$out" | tail -40
  case "$rc" in
    0) dr_pass "matrix-$short" "场景 $s" "通过" ;;
    2) dr_fail "matrix-$short" "场景 $s" "参数错误 exit 2"; overall=1 ;;
    3) dr_step "matrix-$short" "场景 $s" env_unmet "环境前置不满足 exit 3（未真实执行）"; env_unmet=1; DR_ENV_UNMET=1 ;;
    *) dr_fail "matrix-$short" "场景 $s" "失败 exit $rc：$(printf '%s' "$out" | tail -3)"; overall=1 ;;
  esac
  printf '%s\t%s\texit=%d\n' "$short" "$s" "$rc" >> "$summary"
done

dr_write_report
{
  printf '# T-6.1 演练矩阵汇总\n\n'
  printf -- '- 时间：%s\n' "$DR_RUN_TS"
  printf -- '- 模式：%s\n' "$([ "$DRY_RUN" = "1" ] && printf 'dry-run（**不得作为验收证据**）' || printf '真实执行')"
  printf -- '- 场景结果：\n\n'
  printf '| 场景 | 脚本 | 退出码 |\n|---|---|---|\n'
  cat "$summary"
  printf '\n> 退出码 3 = 环境前置不满足（该场景未真实执行）——整体判定 env_unmet，**不得**作为 V-6 验收证据。\n'
  printf '> 共享 PG 备份恢复 PITR 的 RTO/RPO 仍为**占位**（客户书面确认前不作判据，沿用 P2-3 口径）。\n'
} > "$DR_EVIDENCE_DIR/matrix-summary.md"

printf '汇总：%s\n' "$DR_EVIDENCE_DIR/matrix-summary.md"
if [ "$overall" -ne 0 ]; then
  exit "$DR_EXIT_FAIL"
fi
if [ "$env_unmet" -ne 0 ]; then
  exit "$DR_EXIT_ENV"
fi
exit "$DR_EXIT_OK"
