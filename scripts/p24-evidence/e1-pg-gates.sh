#!/usr/bin/env bash
# scripts/p24-evidence/e1-pg-gates.sh
#
# ── 对应登记项 ────────────────────────────────────────────────────────────────
#   PRE-A-17：真 PostgreSQL 环境未就绪 → 涉 PG 的门控用例整体 SKIP
#     （T-1.2/T-1.3/T-1.4/T-1.5/T-1.6/T-2.1/T-2.3 等）
#
# ── 本脚本解决什么 ────────────────────────────────────────────────────────────
#   把这些门控用例的取证动作**一次编排完**：给一个可连的 PG，跑完出证据，
#   环境一到就是一条命令，不用再逐个包找 `-run` 与 env 名。
#
# ── 反造假口径（本脚本的存在意义）─────────────────────────────────────────────
#   `ADMIN_TEST_PG_DSN` 未生效时，这些用例会**静默 t.Skip** —— 测试全绿但等于没跑。
#   所以本脚本在跑完后**强制断言输出里没有 `--- SKIP`**：
#   带了 DSN 还出现 SKIP ⇒ 判 FAIL（说明连不上/变量没传进去），绝不当通过。
#
# ── 前置 ─────────────────────────────────────────────────────────────────────
#   * 能连的真 PG（建议按本体 §3.2 D-3 共享库拓扑，账号最小权限）
#   * Go ≥ 1.26（gateway/go.mod 要求；本机 Windows 上 Go 1.20 无法编译 → 用 .248 或 CI）
#   * psql 客户端（可选；缺失则跳过"版本/表清单"两项，不判失败）
#
# ── 用法 ─────────────────────────────────────────────────────────────────────
#   ./e1-pg-gates.sh --dsn 'postgres://u:p@h:5432/db?sslmode=require'
#   ./e1-pg-gates.sh --dsn "$DSN" --race        # 加 -race（需 gcc）
#   ./e1-pg-gates.sh --dsn "$DSN" --all         # 不加 -run，跑整包（慢，兜底用）
#   ./e1-pg-gates.sh --dry-run                  # 只打印将执行的命令
#
#   环境变量等价：ADMIN_TEST_PG_DSN（脚本未给 --dsn 时读取）
#
# ── 退出码 ───────────────────────────────────────────────────────────────────
#   0 通过（PASS；skip 项不拦截）｜1 存在失败步骤｜2 参数错误｜3 环境前置不满足
#   ★ 3 与 0 严格区分：3 = 没跑成，不得作为 PRE-A-17 的闭环证据。
#
# ── 证据 ─────────────────────────────────────────────────────────────────────
#   默认落 docs/verify/multicluster/evidence/PRE-A-17-pg-gates/<时间戳>/
#     steps.jsonl（逐步记录）/ report.json / evidence.md / go-test.log
#   ⚠️ 脚本只写文件**不提交**；归档由执行人 `cd docs && git add` 决定。
#   ⚠️ DSN 中含口令 → 记录与证据内一律脱敏（用户/主机保留，口令替换为 ***）。

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# _lib.sh 在 source 时就会给 DRILL_OUT 赋默认值（scripts/drills/.runs），
# 所以要在 source **之前**记住用户是否显式指定，source 后再决定覆盖。
_PRE_OUT="${DRILL_OUT:-}"
# shellcheck source=../drills/_lib.sh
source "$HERE/../drills/_lib.sh"

DRILL_ID="PRE-A-17-pg-gates"
DRILL_TITLE="PRE-A-17 真 PG 门控用例取证"
# 证据默认落 docs 库的 evidence 目录（与演练的 .runs 区分：这是验收证据，随 docs 归档）
if [ -n "${_PRE_OUT:-}" ]; then
  DRILL_OUT="$_PRE_OUT"
else
  DRILL_OUT="$HERE/../../docs/verify/multicluster/evidence"
fi

DSN_IN="${ADMIN_TEST_PG_DSN:-}"
USE_RACE=0
RUN_ALL=0
NEW_ARGS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --dsn)   DSN_IN="${2:-}"; shift 2; continue ;;
    --dsn=*) DSN_IN="${1#*=}"; shift; continue ;;
    --race)  USE_RACE=1; shift; continue ;;
    --all)   RUN_ALL=1; shift; continue ;;
    -h|--help)
      sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
  esac
  NEW_ARGS+=("$1"); shift
done

if [ ${#NEW_ARGS[@]} -gt 0 ]; then
  dr_parse_common "${NEW_ARGS[@]}"
else
  dr_parse_common
fi

# DSN 脱敏（证据里不留口令）
mask_dsn() {
  printf '%s' "$1" | sed -E 's#(://[^:/@]+):[^@]*@#\1:***@#'
}

dr_init

DSN_MASKED="$(mask_dsn "$DSN_IN")"
export ADMIN_TEST_PG_DSN="$DSN_IN"

printf '== %s ==\n证据目录：%s\nPG：%s\n\n' "$DRILL_TITLE" "$DR_EVIDENCE_DIR" "$DSN_MASKED"

# ---------- ① 环境前置 ----------
if ! command -v go >/dev/null 2>&1; then
  dr_step env "Go 工具链" env_unmet "未安装/不在 PATH → 无法编译 gateway（本机 Windows Go 1.20 不满足 go.mod 要求的 1.26）"
  DR_ENV_UNMET=1
fi

GO_VER=""
if command -v go >/dev/null 2>&1; then
  GO_VER="$(go version 2>&1 || true)"
  printf '%s\n' "$GO_VER" > "$DR_EVIDENCE_DIR/go-version.txt"
  # 从 "go version go1.26.0 linux/amd64" 里取 1.26
  GOMIN="$(printf '%s' "$GO_VER" | sed -nE 's#.*go([0-9]+)\.([0-9]+).*#\1\2#p')"
  if [ -n "$GOMIN" ] && [ "$GOMIN" -lt 126 ] 2>/dev/null; then
    dr_step env "Go 版本 ≥ 1.26" env_unmet "$GO_VER（低于 gateway/go.mod 要求，编译必失败）"
    DR_ENV_UNMET=1
  else
    dr_pass env "Go 版本" "$GO_VER"
  fi
fi

if [ "$DRY_RUN" != "1" ] && [ "$DR_ENV_UNMET" = "1" ]; then
  printf '\n环境前置不满足，未执行任何取证动作。\n' >&2
  dr_compute_exit_code 0
  exit "$DR_FINAL_CODE"
fi

# ---------- ② PG 连通与形态（只读）----------
if command -v psql >/dev/null 2>&1 && [ -n "$DSN_IN" ]; then
  if dr_exec_ro e1-conn "PG 连通性（select 1）" 'psql "$ADMIN_TEST_PG_DSN" -tAc "select 1"'; then
    dr_exec_ro e1-version "PG 版本" 'psql "$ADMIN_TEST_PG_DSN" -tAc "select version()"'
    # 表清单：用于与 PRE-B-8 的「13 张表」口径核对（不断言具体数字，只记录事实）
    dr_exec_ro e1-tables "已建表清单" \
      'psql "$ADMIN_TEST_PG_DSN" -tAc "select table_name from information_schema.tables where table_schema=current_schema() order by 1"'
    dr_exec_ro e1-ssl "连接加密（sslmode 生效证据）" \
      'psql "$ADMIN_TEST_PG_DSN" -tAc "select ssl, version from pg_stat_ssl where pid=pg_backend_pid()"'
  else
    DR_ENV_UNMET=1
    dr_step env "PG 连通性" env_unmet "psql 无法连接（$DSN_MASKED）→ 门控用例届时仍会整体 SKIP"
  fi
elif [ -z "$DSN_IN" ]; then
  dr_step env "PG 连接串" env_unmet "未提供 --dsn 且 ADMIN_TEST_PG_DSN 为空 → 门控用例会整体 SKIP（PRE-A-17 未解除）"
  DR_ENV_UNMET=1
else
  dr_skip e1-psql "psql 客户端" "未安装 psql → 跳过版本/表清单/加密三项（不判失败，但不作为闭环证据）"
fi

if [ "$DR_ENV_UNMET" = "1" ]; then
  printf '\n前置不满足（含 PG 不可连），未执行门控用例。\n' >&2
  dr_compute_exit_code 0
  exit "$DR_FINAL_CODE"
fi

# ---------- ③ 门控用例 ----------
RUN_RE='PG|Postgres|Postgre'
PKGS='./gateway-admin-service/ ./gateway-admin-service/sqlutil/'
GO_TEST_LOG="$DR_EVIDENCE_DIR/go-test.log"

build_cmd() {
  local c="cd '$HERE/../../gateway' && go test $PKGS"
  if [ "$RUN_ALL" = "0" ]; then
    c="$c -run '$RUN_RE'"
  fi
  c="$c -v -count=1 -timeout 30m"
  if [ "$USE_RACE" = "1" ]; then
    c="$c -race"
  fi
  printf '%s' "$c"
}

if [ "$DRY_RUN" = "1" ]; then
  dr_dryrun e1-test "运行 PG 门控用例" "将执行：$(build_cmd)"
  dr_dryrun e1-noskip "断言无 SKIP" "将检查 go-test.log 不含 '--- SKIP'"
else
  printf '\n>> 运行门控用例（包：%s）…\n' "$PKGS"
  TEST_OUT="$(bash -c "$(build_cmd)" 2>&1)"
  TEST_RC=$?
  printf '%s\n' "$TEST_OUT" > "$GO_TEST_LOG"

  if [ $TEST_RC -eq 0 ]; then
    dr_pass e1-test "运行 PG 门控用例" "go test exit 0（完整输出见 go-test.log）"
  else
    dr_fail e1-test "运行 PG 门控用例" "go test exit $TEST_RC（完整输出见 go-test.log）"
  fi

  # ★ 核心反造假断言：带 DSN 仍 SKIP == 没跑
  SKIPPED="$(printf '%s' "$TEST_OUT" | grep -c '^--- SKIP' || true)"
  if [ "${SKIPPED:-0}" -gt 0 ]; then
    dr_fail e1-noskip "断言无 SKIP" "出现 $SKIPPED 个 SKIP：DSN 未生效或库不可用 → 本次不构成 PRE-A-17 闭环证据"
  else
    dr_pass e1-noskip "断言无 SKIP" "无 SKIP，门控用例真实执行"
  fi

  # 统计（记录事实，不用作判据）
  P="$(printf '%s' "$TEST_OUT" | grep -c '^--- PASS' || true)"
  F="$(printf '%s' "$TEST_OUT" | grep -c '^--- FAIL' || true)"
  dr_pass e1-summary "用例统计" "PASS=${P:-0} FAIL=${F:-0} SKIP=${SKIPPED:-0}（判据是上面的无-SKIP 断言）"
fi

printf '\n完成。证据：%s\n' "$DR_EVIDENCE_DIR"
dr_write_evidence_md "- 门控用例清单与 T-1.x 的对应关系（按实际执行的 -run 结果填写）
- 若出现 SKIP，逐条说明是哪个环境变量/前置缺失（**不得写"通过"**）"
dr_compute_exit_code 0
exit "$DR_FINAL_CODE"
