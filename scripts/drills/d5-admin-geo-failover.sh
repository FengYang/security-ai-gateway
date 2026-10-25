#!/usr/bin/env bash
# scripts/drills/d5-admin-geo-failover.sh — P2-4 T-6.1 演练矩阵 ⑤：管理面跨机房 failover。
#
# 场景（A1(7) 口径）：admin-service **异地 active-standby** 拉起 + 从侧**只读降级**：
#   1. 主中心管理面故障 → 从中心拉起 admin-service（active-standby）
#   2. 机房分区期间：以共享 PG **主所在中心**为唯一写入侧；从侧进入**只读降级**
#      （写请求 503 + 重试入队），禁止双主脑裂
#   3. 管理面恢复目标 RTO ≤ 30min、RPO ≤ 5min（§6.4 A4(6)，设计目标；本脚本登记**实测**）
#   4. 分区恢复后自动解除只读降级，恢复正常读写
#
# ★ PITR 备份恢复的 RTO/RPO 仅为占位（客户书面确认前不作验收判据，沿用 P2-3 口径）。
#
# 注入环境变量（演练环境）：
#   ADMIN_FAILOVER_CMD     主侧故障 + 从侧拉起管理面（脚本注入 SITE_PRIMARY / SITE_STANDBY）
#   ADMIN_CLEAR_CMD        解除主侧故障（脚本注入 SITE_PRIMARY）
#   ADMIN_WRITABLE_CHECK   从侧写可用性检查：只读降级时应失败/503（脚本注入 SITE）
#   ADMIN_READONLY_CHECK   从侧只读降级标志检查（脚本注入 SITE）
#   ADMIN_URL_PRIMARY / ADMIN_URL_STANDBY  两中心管理面基址
#   PG_PRIMARY_DSN         共享 PG 主库连接串（写侧唯一性判定）
#
# 退出码：0 通过｜1 失败｜2 参数错误｜3 环境前置不满足。

set -uo pipefail

_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$_SELF_DIR/_lib.sh"

SITE_PRIMARY="site-a"
SITE_STANDBY="site-b"
RTO_TARGET_SEC=1800 # §6.4 A4(6)：管理面异地 RTO ≤ 30min

while [ $# -gt 0 ]; do
  case "$1" in
    --primary-site) SITE_PRIMARY="${2:-}"; shift 2 ;;
    --standby-site) SITE_STANDBY="${2:-}"; shift 2 ;;
    --rto-target) RTO_TARGET_SEC="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --out) DRILL_OUT="${2:-}"; shift 2 ;;
    --out=*) DRILL_OUT="${1#*=}"; shift ;;
    -h|--help)
      printf '用法：d5-admin-geo-failover.sh [--primary-site site-a] [--standby-site site-b] [--rto-target 1800] [--dry-run] [--out DIR]\n'
      exit 0 ;;
    *) echo "未知参数：$1" >&2; exit "$DR_EXIT_ARGS" ;;
  esac
done

DRILL_ID="d5-admin-geo-failover"
DRILL_TITLE="管理面跨机房 failover（$SITE_PRIMARY 故障 → $SITE_STANDBY 拉起 + 只读降级）"
dr_init

# ---------- 阶段 1：预检 ----------
dr_step "1-precheck" "预检" pass "开始"
if ! dr_require_env "管理面 failover 钩子" ADMIN_FAILOVER_CMD; then
  dr_write_report
  dr_write_evidence_md "- failover 编排方式（人工拉起 / Argo CD / 客户 CI）：TODO(人工)
- 两机房网络分区手段：TODO(人工)
- **PITR 备份恢复 RTO/RPO：占位**（客户书面确认前不作判据，沿用 P2-3 口径）"
  exit "$DR_EXIT_ENV"
fi
if ! dr_require_env "管理面恢复钩子" ADMIN_CLEAR_CMD; then
  dr_write_report; dr_write_evidence_md "- 恢复方式：TODO(人工)"; exit "$DR_EXIT_ENV"
fi
if ! dr_require_env "从侧写可用性检查钩子" ADMIN_WRITABLE_CHECK; then
  dr_write_report; dr_write_evidence_md "- 只读降级判定方式：TODO(人工)"; exit "$DR_EXIT_ENV"
fi
if [ -z "${PG_PRIMARY_DSN:-}" ]; then
  dr_step "env" "共享 PG 主库连接串" env_unmet "缺少 PG_PRIMARY_DSN（写侧唯一性判定需要）"
  DR_ENV_UNMET=1
  dr_write_report; dr_write_evidence_md "- PG 主库连接串：TODO(人工)"; exit "$DR_EXIT_ENV"
fi
if [ -n "${ADMIN_URL_PRIMARY:-}" ]; then
  c="$(dr_http_code "$ADMIN_URL_PRIMARY")"
  case "$c" in
    2?? | 3?? | 401 | 403) dr_pass "1.1-primary" "主中心管理面基线可达" "HTTP $c" ;;
    *) dr_fail "1.1-primary" "主中心管理面基线可达" "HTTP $c"; dr_write_report; exit "$DR_EXIT_FAIL" ;;
  esac
else
  dr_skip "1.1-primary" "主中心管理面基线可达" "未配置 ADMIN_URL_PRIMARY"
fi
dr_step "1-precheck" "预检" pass "预检完成"

# ---------- 阶段 2：执行（主侧故障 + 从侧拉起） ----------
fa_start_ms="$(date +%s%3N)"
export SITE_PRIMARY SITE_STANDBY
dr_exec "2-failover" "主侧故障并从侧拉起管理面" "$ADMIN_FAILOVER_CMD"

# ---------- 阶段 3：观测 ----------
if [ -n "${ADMIN_URL_STANDBY:-}" ]; then
  c="$(dr_http_code "$ADMIN_URL_STANDBY")"
  case "$c" in
    2?? | 3?? | 401 | 403) dr_pass "3.1-standby-up" "从侧管理面已拉起" "HTTP $c $ADMIN_URL_STANDBY" ;;
    *) dr_fail "3.1-standby-up" "从侧管理面已拉起" "HTTP $c $ADMIN_URL_STANDBY（未拉起）" ;;
  esac
else
  dr_skip "3.1-standby-up" "从侧管理面已拉起" "未配置 ADMIN_URL_STANDBY"
fi
# 3.2 只读降级：从侧写请求应被拒（503 / 重试入队），不得双主脑裂
export SITE="$SITE_STANDBY"
if dr_dryrun_dependent "3.2-readonly-degrade" "从侧只读降级（写拒绝，禁止脑裂）" "须在从侧拉起后成立；dry-run 不断言"; then
  :
else
  wout="$(bash -c "$ADMIN_WRITABLE_CHECK" 2>&1)"; wrc=$?
  printf '%s' "$wout" > "$DR_EVIDENCE_DIR/standby-write-check.txt"
  if [ $wrc -ne 0 ] || printf '%s' "$wout" | grep -qiE "503|read[- ]?only|只读|降级|retry|重试"; then
    dr_pass "3.2-readonly-degrade" "从侧只读降级（写拒绝，禁止脑裂）" "$wout"
  else
    dr_fail "3.2-readonly-degrade" "从侧只读降级（写拒绝，禁止脑裂）" "从侧写竟然成功：$wout（⇒ 存在双主脑裂风险，立即中止）"
  fi
fi
# 3.3 只读降级标志
if dr_dryrun_dependent "3.3-readonly-flag" "只读降级标志可见" "须在从侧拉起后成立；dry-run 不断言"; then
  :
elif [ -n "${ADMIN_READONLY_CHECK:-}" ]; then
  rout="$(bash -c "$ADMIN_READONLY_CHECK" 2>&1)"; rrc=$?
  if [ $rrc -eq 0 ]; then
    dr_pass "3.3-readonly-flag" "只读降级标志可见" "$rout"
  else
    dr_fail "3.3-readonly-flag" "只读降级标志可见" "exit $rrc：$rout"
  fi
else
  dr_skip "3.3-readonly-flag" "只读降级标志可见" "未注入 ADMIN_READONLY_CHECK"
fi
# 3.4 RTO 实测登记
fa_end_ms="$(date +%s%3N)"
if dr_dryrun_dependent "3.4-rto" "管理面 failover RTO（实测登记）" "dry-run 未真实 failover，RTO 不可测"; then
  :
else
  DR_RTO_SEC="$(awk "BEGIN{printf \"%.1f\", ($fa_end_ms-$fa_start_ms)/1000}")"
  dr_pass "3.4-rto" "管理面 failover RTO（实测登记）" "${DR_RTO_SEC}s（设计目标 ≤${RTO_TARGET_SEC}s / 30min，§6.4 A4(6)）"
fi

# ---------- 阶段 4：确认 ----------
if ! dr_confirm_gate "确认从侧管理面已拉起、写入被正确拒绝（只读降级）、无脑裂双写？"; then
  dr_write_report
  dr_write_evidence_md "- 脑裂判定：TODO(人工)
- 从侧只读降级的业务影响：TODO(人工)"; exit "$DR_EXIT_FAIL"
fi

# ---------- 阶段 5：记录（分区恢复） ----------
export SITE_PRIMARY
dr_exec "5-clear" "解除主侧故障（分区恢复）" "$ADMIN_CLEAR_CMD"
export SITE="$SITE_STANDBY"
if dr_dryrun_dependent "5.1-readonly-released" "分区恢复后解除只读降级" "须在解除主侧故障后成立；dry-run 未恢复故不断言"; then
  :
else
  wout2="$(bash -c "$ADMIN_WRITABLE_CHECK" 2>&1)"; wrc2=$?
  if [ $wrc2 -eq 0 ]; then
    dr_pass "5.1-readonly-released" "分区恢复后解除只读降级" "$wout2"
  else
    dr_fail "5.1-readonly-released" "分区恢复后解除只读降级" "写仍被拒：$wout2（须人工确认降级解除流程）"
  fi
fi
dr_write_report
dr_write_evidence_md "- RPO 实测（异地异步复制丢数据量）：TODO(人工)（§6.4 设计目标 RPO ≤5min）
- 从侧拉起耗时明细（DNS/证书/PG 连接/配置）：TODO(人工)
- 分区期间业务降级口径与客户沟通：TODO(人工)
- **PITR 备份恢复 RTO/RPO：占位**（客户书面确认前不得作验收判据，沿用 P2-3 口径）"
printf '报告：%s\n' "$DR_EVIDENCE_DIR/report.json"
# 退出码由主流程一处决定（★ EXIT trap 只做收尾写报告，不改变已决定的退出状态）。
dr_compute_exit_code $?
exit "$DR_FINAL_CODE"
