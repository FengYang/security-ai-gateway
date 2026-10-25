#!/usr/bin/env bash
# scripts/drills/d3-storage-failover.sh — P2-4 T-6.1 演练矩阵 ③：存储主从切换（共享 PG）。
#
# 场景：共享 PostgreSQL 主从切换，验证
#   · 主库切换后应用**自动恢复读写**（连接重建 / 故障转移参数生效）
#   · 切换期间**无脑裂双写**（写侧唯一；异地/同城按 §3.2 形态参数矩阵：主所在中心为唯一写入侧）
#   · 计费/租户数据在切换后**一致**（对账抽样）
#
# ★ 口径声明：共享 PG 的 **PITR 备份恢复 RTO/RPO 仅为占位**——客户书面确认前**不得**作为验收判据
#   （沿用 P2-3 口径；O2(6)）。本脚本只登记**主从切换**的实测 RTO，不产出 PITR 判据。
#
# 注入环境变量（演练环境）：
#   PG_FAILOVER_CMD   触发主从切换（脚本注入 PG_PRIMARY / PG_STANDBY）
#   PG_WRITABLE_CMD   写可用性检查（脚本注入 DSN；应返回 0）
#   PG_READ_CHECK_CMD  读一致性/主侧检查（脚本注入 DSN）
#   PG_RECONCILE_CMD  对账抽样（脚本注入 DSN）；比较切换前后关键表行数/校验和
#   PG_PRIMARY_DSN / PG_STANDBY_DSN  两端连接串
#
# 退出码：0 通过｜1 失败｜2 参数错误｜3 环境前置不满足。

set -uo pipefail

_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$_SELF_DIR/_lib.sh"

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --out) DRILL_OUT="${2:-}"; shift 2 ;;
    --out=*) DRILL_OUT="${1#*=}"; shift ;;
    -h|--help)
      printf '用法：d3-storage-failover.sh [--dry-run] [--out DIR]\n'
      exit 0 ;;
    *) echo "未知参数：$1" >&2; exit "$DR_EXIT_ARGS" ;;
  esac
done

DRILL_ID="d3-storage-failover"
DRILL_TITLE="存储主从切换（共享 PostgreSQL）"
dr_init

# ---------- 阶段 1：预检 ----------
dr_step "1-precheck" "预检" pass "开始"
if ! dr_require_env "主从切换钩子" PG_FAILOVER_CMD; then
  dr_write_report
  dr_write_evidence_md "- 切换方式（Patroni switchover / pg_ctl promote / 云托管控制台）：TODO(人工)
- PITR 备份恢复 RTO/RPO：**占位**（客户书面确认前不作判据，沿用 P2-3 口径）"
  exit "$DR_EXIT_ENV"
fi
if ! dr_require_env "写可用性检查钩子" PG_WRITABLE_CMD; then
  dr_write_report; dr_write_evidence_md "- 写可用性检查方式：TODO(人工)"; exit "$DR_EXIT_ENV"
fi
if ! dr_require_env "主库连接串" PG_PRIMARY_DSN; then
  dr_write_report; dr_write_evidence_md "- PG_PRIMARY_DSN：TODO(人工)"; exit "$DR_EXIT_ENV"
fi
export PG_PRIMARY="${PG_PRIMARY_DSN}"
export PG_STANDBY="${PG_STANDBY_DSN:-}"
# 写可用性检查会写库 ⇒ 属"变更类"动作，dry-run 下不执行。
dr_exec "1.1-writable-before" "切换前写可用性" "$PG_WRITABLE_CMD"
if [ -n "${PG_RECONCILE_CMD:-}" ]; then
  export DSN="$PG_PRIMARY"
  before_sum="$(bash -c "$PG_RECONCILE_CMD" 2>&1)"; rc=$?
  if [ $rc -eq 0 ]; then
    dr_pass "1.2-checksum-before" "切换前数据校验和快照" "$before_sum"
    printf '%s' "$before_sum" > "$DR_EVIDENCE_DIR/pg-checksum-before.txt"
  else
    dr_fail "1.2-checksum-before" "切换前数据校验和快照" "exit $rc：$before_sum"
  fi
else
  dr_skip "1.2-checksum-before" "切换前数据校验和快照" "未注入 PG_RECONCILE_CMD"
fi
dr_step "1-precheck" "预检" pass "预检完成"

# ---------- 阶段 2：执行（切换）----------
sw_start_ms="$(date +%s%3N)"
dr_exec "2-switchover" "触发主从切换" "$PG_FAILOVER_CMD"

# ---------- 阶段 3：观测（恢复读写）----------
dr_exec "3.1-writable-after" "切换后写可用性" "$PG_WRITABLE_CMD"
if [ -n "${PG_READ_CHECK_CMD:-}" ]; then
  export DSN="$PG_PRIMARY"
  dr_exec_ro "3.2-read-check" "切换后读一致性检查" "$PG_READ_CHECK_CMD"
else
  dr_skip "3.2-read-check" "切换后读一致性检查" "未注入 PG_READ_CHECK_CMD"
fi
# RTO（切换动作 → 写恢复可用）
sw_end_ms="$(date +%s%3N)"
if dr_dryrun_dependent "3.3-rto" "主从切换 RTO（实测登记）" "dry-run 未真实切换，RTO 不可测"; then
  :
else
  DR_RTO_SEC="$(awk "BEGIN{printf \"%.3f\", ($sw_end_ms-$sw_start_ms)/1000}")"
  dr_pass "3.3-rto" "主从切换 RTO（实测登记）" "${DR_RTO_SEC}s（仅主从切换，不含 PITR 恢复）"
fi

# ---------- 阶段 4：确认 ----------
if ! dr_confirm_gate "确认切换后读写正常、无脑裂双写、数据一致？"; then
  dr_write_report
  dr_write_evidence_md "- 脑裂双写检查：TODO(人工)
- 切换对业务的影响：TODO(人工)"; exit "$DR_EXIT_FAIL"
fi

# ---------- 阶段 5：记录（对账）----------
if [ -n "${PG_RECONCILE_CMD:-}" ]; then
  export DSN="$PG_PRIMARY"
  after_sum="$(bash -c "$PG_RECONCILE_CMD" 2>&1)"; rc=$?
  if [ $rc -eq 0 ]; then
    printf '%s' "$after_sum" > "$DR_EVIDENCE_DIR/pg-checksum-after.txt"
    if [ -f "$DR_EVIDENCE_DIR/pg-checksum-before.txt" ] && \
      [ "$(cat "$DR_EVIDENCE_DIR/pg-checksum-before.txt")" = "$after_sum" ]; then
      dr_pass "5.1-reconcile" "切换前后数据一致" "checksum 相同：$after_sum"
    else
      dr_fail "5.1-reconcile" "切换前后数据一致" "checksum 变化：before=[$(cat "$DR_EVIDENCE_DIR/pg-checksum-before.txt" 2>/dev/null)] after=$after_sum"
    fi
  else
    dr_fail "5.1-reconcile" "切换前后数据一致" "exit $rc：$after_sum"
  fi
fi
dr_write_report
dr_write_evidence_md "- 切换拓扑（主/备所在中心）：TODO(人工)
- 写侧唯一性（无脑裂）判定：TODO(人工)
- **PITR 备份恢复 RTO/RPO：占位**（客户书面确认前不得作验收判据，沿用 P2-3 口径）"
printf '报告：%s\n' "$DR_EVIDENCE_DIR/report.json"
# 退出码由主流程一处决定（★ EXIT trap 只做收尾写报告，不改变已决定的退出状态）。
dr_compute_exit_code $?
exit "$DR_FINAL_CODE"
