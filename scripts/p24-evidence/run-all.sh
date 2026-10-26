#!/usr/bin/env bash
# scripts/p24-evidence/run-all.sh
#
# 依次跑表一 6 条取证脚本，汇总退出码。
#
# 纪律：**只汇总，不吞结论**。任一脚本 exit 3（环境未就绪）就如实显示 3，
#       绝不把"没跑成"折叠成"通过"；汇总表的结论列也按最差项给出。
#
# 用法：
#   ./run-all.sh --dsn "$PG_DSN" [其它参数透传给 e1]
#   ./run-all.sh --only e1,e6
#   ./run-all.sh --dry-run
#
# 退出码：0 全部 0｜1 任一失败｜3 存在环境未就绪且无失败（= 未取得的证据，非通过）

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DRY=""
ONLY=""
PASS_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY="--dry-run"; PASS_ARGS+=("--dry-run"); shift; continue ;;
    --only)    ONLY="${2:-}"; shift 2; continue ;;
    --only=*)  ONLY="${1#*=}"; shift; continue ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  esac
  PASS_ARGS+=("$1"); shift
done

want() {
  [ -z "$ONLY" ] && return 0
  case ",$ONLY," in *",$1,"*) return 0 ;; esac
  return 1
}

declare -a IDS=() CODES=()
run_one() {
  local id="$1"; shift
  want "$id" || return 0
  printf '\n================ %s ================\n' "$id"
  bash "$HERE/$id"*.sh "${PASS_ARGS[@]:-}"
  local rc=$?
  IDS+=("$id"); CODES+=("$rc")
  printf -- '---- %s 退出码 %s ----\n' "$id" "$rc"
}

run_one e1
run_one e2
run_one e3
run_one e4
run_one e5
run_one e6

printf '\n================ 汇总 ================\n'
printf '%-10s %-6s %s\n' 项 退出码 含义
worst=0
for i in "${!IDS[@]}"; do
  rc="${CODES[$i]}"
  case "$rc" in
    0) word="通过（skip 项见报告）" ;;
    1) word="**存在失败**" ;;
    2) word="参数错误" ;;
    3) word="**环境未就绪（未取得证据）**" ;;
    *) word="未知" ;;
  esac
  printf '%-10s %-6s %s\n' "${IDS[$i]}" "$rc" "$word"
  # 最差项：1 最重；其次 3；2 视同 1
  if [ "$rc" = "1" ] || [ "$rc" = "2" ]; then worst=1
  elif [ "$rc" = "3" ] && [ "$worst" = "0" ]; then worst=3; fi
done

if [ -n "$DRY" ]; then
  printf '\n注意：本次为 --dry-run，产出的报告 executed=false，**不得作为验收证据**。\n'
fi
exit "$worst"
