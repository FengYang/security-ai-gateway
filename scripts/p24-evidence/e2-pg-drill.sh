#!/usr/bin/env bash
# scripts/p24-evidence/e2-pg-drill.sh
#
# ── 对应登记项 ────────────────────────────────────────────────────────────────
#   PRE-B-1：共享 PG 实例真机验证（拓扑 / 连接串 / 账号最小权限 / sslmode）
#   PRE-B-2：迁移演练（双跑 → 切换 → 回滚）
#   PRE-B-3：PG 备份/恢复（PITR）
#   PRE-B-4：PG 故障切换 / 分区行为
#
# ── 能自动化的部分 vs 只能人工的部分（本脚本只做前者，后者生成待填清单）──────
#   自动：PG 版本/当前账号权限/ssl 状态/主从复制状态/WAL 归档开关
#         `admin-service migrate -action plan|verify`（均为只读）
#   人工：真正的「双跑切换」（要动生产/演练库的写入侧）、PITR 恢复（要操作备份介质）、
#         主从切换（要客户 DB 运维在库侧执行）
#   ★ 脚本不会代替人工判定这些项，只把机器可采的事实钉在证据里，
#     并把人工项写成 `TODO(人工)` 占位（dr_write_evidence_md 的口径）。
#
# ── 前置 ─────────────────────────────────────────────────────────────────────
#   --to <PG DSN>        目标共享库（生产须 sslmode=require/verify-full，禁用 disable）
#   --from <sqlite 路径> 迁移源（PRE-B-2 用；缺失则只跑库侧检查）
#   --bin <admin-service> 已编译的 admin-service 二进制（`go build -o admin-service ./gateway-admin-service`）
#   psql 客户端（缺失则只跑 migrate，不判失败）
#
# ── 用法 ─────────────────────────────────────────────────────────────────────
#   ./e2-pg-drill.sh --to "$PG_DSN" --from /data/tenant.db --bin ./gateway-admin-service/admin-service
#   ./e2-pg-drill.sh --to "$PG_DSN" --dry-run
#
# ── 退出码 ───────────────────────────────────────────────────────────────────
#   0 通过｜1 存在失败步骤｜2 参数错误｜3 环境前置不满足（= 没取证，不得当闭环证据）

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_PRE_OUT="${DRILL_OUT:-}"
# shellcheck source=../drills/_lib.sh
source "$HERE/../drills/_lib.sh"

DRILL_ID="PRE-B-1-4-pg-drill"
DRILL_TITLE="PRE-B-1~4 共享 PG 真机验证与迁移演练（可自动化部分）"
if [ -n "${_PRE_OUT:-}" ]; then DRILL_OUT="$_PRE_OUT"; else
  DRILL_OUT="$HERE/../../docs/verify/multicluster/evidence"
fi

TO_DSN=""
FROM_DB=""
BIN=""
NEW_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --to)    TO_DSN="${2:-}"; shift 2; continue ;;
    --to=*)  TO_DSN="${1#*=}"; shift; continue ;;
    --from)  FROM_DB="${2:-}"; shift 2; continue ;;
    --from=*) FROM_DB="${1#*=}"; shift; continue ;;
    --bin)   BIN="${2:-}"; shift 2; continue ;;
    --bin=*) BIN="${1#*=}"; shift; continue ;;
    -h|--help) sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  esac
  NEW_ARGS+=("$1"); shift
done
_BEFORE_PARSE_OUT="$DRILL_OUT"
if [ ${#NEW_ARGS[@]} -gt 0 ]; then dr_parse_common "${NEW_ARGS[@]}"; else dr_parse_common; fi
# dry-run 绝不写 docs 证据目录：否则"预演"会被后任误当"证据"归档（DRILL_OUT 只有 --out 会改）
if [ "$DRY_RUN" = "1" ] && [ "$DRILL_OUT" = "$_BEFORE_PARSE_OUT" ]; then
  DRILL_OUT="$(dr_default_out_dir)/p24-evidence"
fi

mask_dsn() { printf '%s' "$1" | sed -E 's#(://[^:/@]+):[^@]*@#\1:***@#'; }
DSN_MASKED="$(mask_dsn "$TO_DSN")"
export PG_DSN="$TO_DSN"

dr_init

printf '== %s ==\n证据目录：%s\n目标库：%s\n源（sqlite）：%s\n\n' \
  "$DRILL_TITLE" "$DR_EVIDENCE_DIR" "${DSN_MASKED:-(未提供)}" "${FROM_DB:-(未提供)}"

# ---------- ① 前置 ----------
if [ -z "$TO_DSN" ]; then
  dr_step env "目标 PG DSN" env_unmet "未提供 --to：PRE-B-1~4 均无法取证"
  DR_ENV_UNMET=1
fi
command -v psql >/dev/null 2>&1 || dr_step env "psql 客户端" env_unmet "缺失 → 库侧检查全部跳过"
[ -n "$BIN" ] && [ -x "$BIN" ] || dr_step env "admin-service 二进制" env_unmet "未提供或不可执行 → 迁移 plan/verify 跳过（先 go build）"

# ---------- ② 库侧事实（只读）----------
# 为什么把 SQL 落到文件而不是 `-c "..."`：
#   命令字符串要进 steps.jsonl 留证，所以不能在里面展开 DSN（会泄露口令）；
#   而不展开就只能把命令整体用单引号包住 —— 那 SQL 里就再也写不了单引号。
#   解法：SQL 进 .sql 文件（文件本身也是证据），命令里只有 `-f "$P24_SQL"`。
P24_SQL="$DR_EVIDENCE_DIR/pg-checks.sql"
cat > "$P24_SQL" <<'SQL'
\echo '=== 版本与当前账号 ==='
select current_user, session_user, version();
\echo '=== 账号权限（期望：rolsuper=f, rolcreaterole=f）==='
select rolname, rolsuper, rolcreaterole, rolcreatedb from pg_roles where rolname = current_user;
\echo '=== 连接加密（sslmode 生效证据）==='
select ssl, version, cipher from pg_stat_ssl where pid = pg_backend_pid();
\echo '=== 复制拓扑（主从）==='
select client_addr, state, sync_state, sent_lsn, replay_lsn from pg_stat_replication;
\echo '=== WAL 与归档（PITR 前提）==='
select name, setting from pg_settings where name in ('archive_mode','archive_command','wal_level','max_wal_senders') order by 1;
\echo '=== 表清单（供 PRE-B-8「13 张表」口径核对）==='
select table_name from information_schema.tables where table_schema = current_schema() order by 1;
SQL
export P24_SQL

if command -v psql >/dev/null 2>&1 && [ -n "$TO_DSN" ]; then
  dr_exec_ro e2-db "库侧事实（版本/权限/加密/复制/归档/表清单）" \
    'psql "$PG_DSN" -f "$P24_SQL"'
else
  dr_skip e2-db "库侧事实采集" "无 psql 或未给 --to"
fi

# ---------- ③ 迁移只读两步 ----------
if [ -n "$BIN" ] && [ -x "$BIN" ] && [ -n "$TO_DSN" ] && [ -n "$FROM_DB" ]; then
  if [ -f "$FROM_DB" ]; then
    dr_exec e2-plan "迁移计划（-action plan，只读）" \
      "'$BIN' migrate -action plan -from '$FROM_DB' -to \"\$PG_DSN\""
    dr_exec e2-verify "迁移对账（-action verify，只读）" \
      "'$BIN' migrate -action verify -from '$FROM_DB' -to \"\$PG_DSN\""
  else
    dr_blocked e2-plan "迁移计划" "源 sqlite 不存在：$FROM_DB"
  fi
else
  dr_skip e2-plan "迁移 plan/verify" "缺 --bin 可执行文件或 --from 源库 → 未执行（不得视为通过）"
fi

# ---------- ④ 人工项（不得由脚本代填）----------
printf '\n完成（可自动化部分）。证据：%s\n' "$DR_EVIDENCE_DIR"
dr_write_evidence_md "\`PRE-B-2\` 双跑 → 切换 → 回滚：切换窗口、回滚触发原因、回滚耗时（秒）、切换后与源库的行数/校验和对账结果
\`PRE-B-3\` PITR：备份方式与介质、恢复目标时间点、恢复耗时（RTO 实测）、恢复后数据一致性核对
\`PRE-B-4\` 主从切换/分区：切换命令与执行人、写入侧唯一性验证、从侧只读降级行为、分区恢复后追平耗时
以上三项须客户 DB 运维在场执行；**脚本未采集到的一律写"未执行"，不得以基线值代填**"
dr_compute_exit_code 0
exit "$DR_FINAL_CODE"
