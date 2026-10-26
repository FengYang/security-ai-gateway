#!/usr/bin/env bash
# scripts/p24-evidence/e5-failover.sh
#
# ── 对应登记项 ────────────────────────────────────────────────────────────────
#   PRE-B-7：管理面跨机房 failover 演练未执行（V-6-2 控制面故障场景）
#
# ── 设计取向：**不重写演练**，只做两件事 ──────────────────────────────────────
#   ① 委派既有演练脚本 scripts/drills/d5-admin-geo-failover.sh（它已经有完整编排、
#      步骤记录与 RTO 测量口径），本脚本不复制它的逻辑——两套实现必然会漂移；
#   ② 把 d5 的产出**归位到验收证据目录**，并在外层补一条"本次结论是否可用于 PRE-B-7"的判断。
#
#   ★ 为什么外层还要判一次：d5 是"演练"脚本（关注过程与 RTO 记录），
#     PRE-B-7 是"验收取证"（关注结论是否可复现）。两者退出码语义一致，但
#     证据归位与"未跑成不得当证据"的口径要在这一层钉住。
#
# ── 前置 ─────────────────────────────────────────────────────────────────────
#   双集群环境（PRE-B-5）+ 演练窗口；d5 自身的环境变量（站点名等）见其 `-h`
#
# ── 用法 ─────────────────────────────────────────────────────────────────────
#   ./e5-failover.sh                       # 用 d5 默认站点名
#   ./e5-failover.sh --primary-site site-a --standby-site site-b --rto-target 1800
#   ./e5-failover.sh --dry-run
#
# ── 退出码 ───────────────────────────────────────────────────────────────────
#   透传 d5 的退出码语义：0 通过｜1 失败｜2 参数错误｜3 环境前置不满足

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_PRE_OUT="${DRILL_OUT:-}"
# shellcheck source=../drills/_lib.sh
source "$HERE/../drills/_lib.sh"

DRILL_ID="PRE-B-7-failover"
DRILL_TITLE="PRE-B-7 管理面跨机房 failover（委派 d5 演练）"
if [ -n "${_PRE_OUT:-}" ]; then DRILL_OUT="$_PRE_OUT"; else
  DRILL_OUT="$HERE/../../docs/verify/multicluster/evidence"
fi

PASS_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; PASS_ARGS+=("--dry-run"); shift; continue ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  esac
  PASS_ARGS+=("$1"); shift
done

DRILL_D5="$HERE/../drills/d5-admin-geo-failover.sh"
dr_init
printf '== %s ==\n证据目录：%s\n委派：%s\n\n' "$DRILL_TITLE" "$DR_EVIDENCE_DIR" "$DRILL_D5"

if [ ! -f "$DRILL_D5" ]; then
  dr_step env "d5 演练脚本" env_unmet "未找到 $DRILL_D5 → PRE-B-7 无法取证"
  DR_ENV_UNMET=1
  dr_compute_exit_code 0; exit "$DR_FINAL_CODE"
fi

# d5 自己也会写报告，落到本证据目录的子目录，避免两套报告互相覆盖
D5_OUT="$DR_EVIDENCE_DIR/d5"
mkdir -p "$D5_OUT"

if [ "$DRY_RUN" = "1" ]; then
  dr_dryrun e5-delegate "委派 d5 演练（dry-run）" \
    "将执行：bash '$DRILL_D5' ${PASS_ARGS[*]:-} --out '$D5_OUT'"
else
  printf '>> 运行 d5（输出见 %s）…\n' "$D5_OUT"
  bash "$DRILL_D5" "${PASS_ARGS[@]:-}" --out "$D5_OUT"
  D5_RC=$?
  case "$D5_RC" in
    0) dr_pass e5-delegate "委派 d5 演练" "exit 0（证据：$D5_OUT）" ;;
    3) dr_step env "委派 d5 演练" env_unmet "exit 3：演练环境前置不满足（双集群/站点参数）→ 非通过"; DR_ENV_UNMET=1 ;;
    *) dr_fail e5-delegate "委派 d5 演练" "exit $D5_RC（证据：$D5_OUT）" ;;
  esac
fi

printf '\n完成。证据：%s\n' "$DR_EVIDENCE_DIR"
dr_write_evidence_md "\`PRE-B-7\` 本次 failover 的实际切换耗时（RTO 实测，秒）与 d5 报告的 rto_sec 是否一致
分区期间：写入侧唯一性如何验证的、从侧是否真的只读降级、有无脑裂迹象
恢复后：管理面可用性恢复时刻、与告警/看板恢复时刻的对照
**若 d5 以 exit 3 结束，本项写"未执行"，不得引用其 dry-run 结果**"
dr_compute_exit_code 0
exit "$DR_FINAL_CODE"
