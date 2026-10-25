#!/usr/bin/env bash
# scripts/drills/_lib.sh — P2-4 T-5.2 / T-6.1 演练脚本共享库（供各 drill 与 traffic-shift.sh source）。
#
# 定位：
#   · 统一退出码语义、步骤记录、证据产出、环境前置检测、--dry-run 语义；
#   · 各 drill 只写"本场景的编排"，公共纪律集中在本文，避免 5 份脚本各写一套。
#
# ★ 纪律 1（D-5 不自研 GSLB）：切流/回切的执行点在**客户既有 DNS/GSLB/云 LB**，
#   脚本不实现调度器，所有变更动作经**外部钩子命令**注入（环境变量 *_CMD）。
#   钩子缺失 ⇒ 记 skip / 环境不满足，**绝不伪称演练通过**。
#
# ★ 纪律 2（不得伪称通过）：本机无双集群/北向环境时，环境前置检测失败 ⇒ 退出码 3，
#   报告中 `result=env_unmet`；与"通过（0）"严格区分。
#
# ★ 纪律 3（--dry-run）：dry-run 只做**只读**预检与计划打印，不执行任何变更动作；
#   报告标记 `executed=false`，dry-run 结果**不得**作为 V-5/V-6 验收证据。
#
# ★ 纪律 4（依赖"真实变更已发生"的断言）：dry-run 下不成立 ⇒ 记 dry-run 步骤而**不判失败**，
#   统一入口 dr_dryrun_dependent；不得在 dry-run 里把"未做的变更"写成 pass。
#
# 退出码：0 通过（skip 不计失败）｜1 存在失败步骤｜2 参数/初始化错误｜3 环境前置不满足。
#
# 用法（脚本内）：
#   source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_lib.sh"
#   DRILL_ID=d1 DRILL_TITLE="单集群数据面故障"; dr_parse_common "$@"; dr_init
#
# 性能注记：步骤记录与报告生成全部用 bash 内建实现（不 fork awk/sed/tr），
#   以免在受限环境（受控沙箱/跳板机）里因大量子进程而出现进程监管开销与挂起。

set -uo pipefail

# ---------- 退出码 ----------
DR_EXIT_OK=0
DR_EXIT_FAIL=1
DR_EXIT_ARGS=2
DR_EXIT_ENV=3

# ---------- 全局状态（由 dr_init 初始化）----------
DRILL_ID="${DRILL_ID:-drill}"
DRILL_TITLE="${DRILL_TITLE:-演练}"
# dr_default_out_dir —— 默认证据输出目录。
#
# ★ 口径：证据目录**优先落在仓库内**（scripts/drills/.runs/），原因有二：
#   1) 留在工作区内 ⇒ 受控环境（沙箱/跳板机）对工作区外路径（如 /tmp）写入受限，
#      会出现"脚本写文件挂起"的环境级故障；
#   2) .runs/ 由 scripts/drills/.gitignore 忽略 ⇒ 演练产物**不会**误入主库提交。
#   脚本被单独拷到跳板机（不在仓库内）时，退回 ${TMPDIR:-/tmp}。
dr_lib_dir() { cd "$(dirname "${BASH_SOURCE[0]}")" && pwd; }

dr_repo_root() {
  local up
  up="$(dr_lib_dir)/../.."
  [ -d "$up/scripts" ] || return 1
  (cd "$up" && pwd)
}

dr_default_out_dir() {
  local root t
  if root="$(dr_repo_root 2>/dev/null)"; then
    printf '%s/scripts/drills/.runs/ga-multicluster-drills' "$root"
    return 0
  fi
  # 不在仓库内：退到系统临时目录；Windows 风格 TMPDIR（带盘符/反斜杠）归一为 /tmp，
  # 避免路径前缀被误解析（Git Bash 下 `C:\...` 会被当成相对路径）。
  t="${TMPDIR:-/tmp}"
  case "$t" in
    [A-Za-z]:* | *\\*) t="/tmp" ;;
  esac
  printf '%s/ga-multicluster-drills' "$t"
}

# 证据输出目录：默认落在仓库内 scripts/drills/.runs/（**不进主库提交**），
# 演练后由执行人把补齐的证据拷贝到 docs 库的 docs/verify/multicluster/（V-8 归档）。
DRILL_OUT="${DRILL_OUT:-$(dr_default_out_dir)}"
DRY_RUN="${DRY_RUN:-0}"
DR_ARGS=()
DR_RUN_TS=""
DR_RUN_DATE=""
DR_EVIDENCE_DIR=""
DR_STEPS_FILE=""
DR_INCIDENTS_FILE=""
DR_FAILED=0
DR_ENV_UNMET=0
DR_REPORT_WRITTEN=0
DR_START_MS=0
DR_EXIT_CODE=""
DR_FINAL_CODE=0
DR_EXIT_MSG_SHOWN=0
# RTO/RPO 实测登记（由 drill 在观测/恢复阶段填写；空 = 未登记）
DR_RTO_SEC="${DR_RTO_SEC:-}"
DR_RPO_SEC="${DR_RPO_SEC:-}"
# JSON 转义结果承载变量（避免命令替换产生子进程）
DR_JSON_ESCAPED=""
DR_JSON_JOINED=""
DR_FIELD=""
DR_RESULT_WORD="pass"

# ---------- 参数解析（公共部分）----------
# 识别 --dry-run、--out <dir>；其余参数存入 DR_ARGS 交调用方处理。
dr_parse_common() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run) DRY_RUN=1; shift ;;
      --out) DRILL_OUT="${2:-}"; shift 2 ;;
      --out=*) DRILL_OUT="${1#*=}"; shift ;;
      *) DR_ARGS+=("$1"); shift ;;
    esac
  done
  if [ -z "$DRILL_OUT" ]; then
    echo "--out 需要非空参数" >&2
    exit "$DR_EXIT_ARGS"
  fi
}

dr_usage_dryrun_note() {
  printf '选项：--dry-run（只读预演，不执行变更）  --out <dir>（证据输出目录，默认 %s）\n' "$DRILL_OUT"
}

# ---------- 时间戳（尽量不 fork）----------
# dr_now_ms —— 毫秒时间戳。bash 5+ 用 EPOCHREALTIME（无子进程）；旧版回退 date。
dr_now_ms() {
  if [ -n "${EPOCHREALTIME:-}" ]; then
    local frac
    frac="${EPOCHREALTIME#*.}"
    printf '%s%s' "${EPOCHREALTIME%%.*}" "${frac:0:3}"
  else
    date +%s%3N
  fi
}

# dr_now_ts —— 演练时间戳（目录名用）。bash 4.2+ 用 printf %(fmt)T；旧版回退 date。
dr_now_ts() {
  if [ -n "${EPOCHSECONDS:-}" ]; then
    printf '%(%Y-%m-%dT%H-%M-%S)T' -1
  else
    date +%Y-%m-%dT%H-%M-%S
  fi
}

# ---------- 初始化 ----------
dr_init() {
  DR_RUN_TS="$(dr_now_ts)"
  DR_RUN_DATE="$(printf '%(%Y-%m-%d)T' -1 2>/dev/null || date +%Y-%m-%d)"
  DR_EVIDENCE_DIR="$DRILL_OUT/$DRILL_ID/$DR_RUN_TS"
  mkdir -p "$DR_EVIDENCE_DIR" || {
    echo "无法创建证据目录 $DR_EVIDENCE_DIR" >&2
    exit "$DR_EXIT_ARGS"
  }
  # 步骤/异常明细直接落在证据目录内（**不**用 mktemp 临时文件）：
  #   · 它们本身就是留证产物（随证据目录一并归档）；
  #   · 避免退出时 rm 临时文件触发路径前缀相关的误删/阻塞风险。
  DR_STEPS_FILE="$DR_EVIDENCE_DIR/steps.jsonl"
  DR_INCIDENTS_FILE="$DR_EVIDENCE_DIR/incidents.txt"
  : > "$DR_STEPS_FILE"
  : > "$DR_INCIDENTS_FILE"
  DR_START_MS="$(dr_now_ms)"
  trap dr_finalize EXIT
  if [ "$DRY_RUN" = "1" ]; then
    printf '[%s] dry-run 模式：只做只读预检与计划打印，**不执行任何变更动作**\n' "$DRILL_ID"
  fi
}

# dr_cleanup_tmp —— 步骤/异常明细是**证据产物**，故意保留（不删除）。
dr_cleanup_tmp() {
  :
}

# ---------- JSON 辅助（纯 bash 实现，避免额外子进程）----------
# dr_json_escape_into <文本> —— 转义结果写入 DR_JSON_ESCAPED。
dr_json_escape_into() {
  local s="${1//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/}"
  s="${s//$'\t'/\\t}"
  DR_JSON_ESCAPED="$s"
}

# dr_json_escape <文本> —— 输出转义后的字符串（保留给外部调用者使用）。
dr_json_escape() {
  dr_json_escape_into "${1:-}"
  printf '%s' "$DR_JSON_ESCAPED"
}

# dr_json_join_into <文件> —— 把文件每行用逗号连接，结果写入 DR_JSON_JOINED。
dr_json_join_into() {
  local line first=1
  DR_JSON_JOINED=""
  [ -f "$1" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$first" -eq 1 ]; then first=0; else DR_JSON_JOINED="$DR_JSON_JOINED,"; fi
    DR_JSON_JOINED="$DR_JSON_JOINED$line"
  done < "$1"
}

dr_json_join() {
  dr_json_join_into "${1:-}"
  printf '%s' "$DR_JSON_JOINED"
}

# dr_field_into <json行> <字段名> —— 取出 "字段":"值" 中的值，结果写入 DR_FIELD（纯 bash 解析）。
dr_field_into() {
  local line="$1" key="$2" val
  case "$line" in
    *"\"$key\":\""*) ;;
    *) DR_FIELD=""; return 1 ;;
  esac
  val="${line#*\"$key\":\"}"
  case "$key" in
    detail) val="${val%\}}"; val="${val%\"}" ;;
    *) val="${val%%\"*}" ;;
  esac
  DR_FIELD="$val"
}

# dr_field_of <json行> <字段名> —— 同上，但直接输出（保留给外部调用者使用）。
dr_field_of() {
  dr_field_into "$1" "$2"
  printf '%s' "$DR_FIELD"
}

# ---------- 步骤记录 ----------
# dr_step <id> <name> <result> <detail>
# result: pass | fail | skip | blocked | dry-run | env_unmet
dr_step() {
  local detail="${4:-}"
  detail="${detail//$'\r'/}"
  dr_json_escape_into "$detail"
  printf '{"id":"%s","name":"%s","result":"%s","detail":"%s"}\n' \
    "$1" "$2" "$3" "$DR_JSON_ESCAPED" >> "$DR_STEPS_FILE"
  printf '  [%s] %-28s %s\n' "$1" "$2" "$3"
}

dr_pass() { dr_step "$1" "$2" pass "${3:-}"; }
dr_skip() { dr_step "$1" "$2" skip "${3:-}"; }
dr_blocked() { dr_step "$1" "$2" blocked "${3:-}"; }
dr_dryrun() { dr_step "$1" "$2" dry-run "${3:-}"; }

# dr_fail <id> <name> <detail> — 记 fail 步骤并登记 incident（置失败标志）
dr_fail() {
  dr_step "$1" "$2" fail "${3:-}"
  printf '%s: %s\n' "$2" "${3:-}" >> "$DR_INCIDENTS_FILE"
  printf '  失败：%s\n' "$2" >&2
  DR_FAILED=1
}

# dr_incident <msg> — 只登记异常（不改变步骤结论）
dr_incident() {
  printf '%s\n' "$1" >> "$DR_INCIDENTS_FILE"
  printf '  异常：%s\n' "$1" >&2
}

# ---------- 执行器 ----------
# dr_exec <id> <name> <cmd> — **变更类**动作：dry-run 下只打印不执行。
dr_exec() {
  local id="$1" name="$2" cmd="$3"
  if [ "$DRY_RUN" = "1" ]; then
    dr_dryrun "$id" "$name" "dry-run 未执行：$cmd"
    return 0
  fi
  local rc output
  output="$(bash -c "$cmd" 2>&1)"
  rc=$?
  if [ $rc -eq 0 ]; then
    dr_pass "$id" "$name" "$output"
  else
    dr_fail "$id" "$name" "exit $rc：$output"
  fi
  return $rc
}

# dr_exec_ro <id> <name> <cmd> — **只读**动作：dry-run 下也执行（读不产生变更）。
dr_exec_ro() {
  local id="$1" name="$2" cmd="$3"
  local rc output
  output="$(bash -c "$cmd" 2>&1)"
  rc=$?
  if [ $rc -eq 0 ]; then
    dr_pass "$id" "$name" "$output"
  else
    # 只读探测失败在预演中也可能是"环境不具备"，按 fail 记录但由调用方决定是否阻断
    dr_fail "$id" "$name" "exit $rc：$output"
  fi
  return $rc
}

# ---------- 环境前置检测 ----------
# dr_require_env <用途> <变量名...> — 缺失 ⇒ 记 env_unmet 步骤并返回 1。
# 调用方应：dr_require_env "北向权重变更" NB_SET_WEIGHT_CMD || exit $DR_EXIT_ENV
dr_require_env() {
  local purpose="$1"; shift
  local missing="" v val
  for v in "$@"; do
    eval "val=\"\${$v:-}\""
    if [ -z "$val" ]; then
      missing="$missing $v"
    fi
  done
  if [ -n "$missing" ]; then
    dr_step "env" "$purpose" env_unmet "缺少环境变量：$missing（本机/当前环境不具备演练前置，须在演练环境注入后重跑）"
    DR_ENV_UNMET=1
    return 1
  fi
  return 0
}

# dr_require_cmd <命令> — 缺失 ⇒ 记 env_unmet 并返回 1。
dr_require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    dr_step "env" "依赖命令 $1" env_unmet "未安装/不在 PATH"
    DR_ENV_UNMET=1
    return 1
  fi
  return 0
}

# ---------- HTTP 探测 ----------
# dr_health_url_of <cluster_id> —— 解析该集群的健康源（§6.4 health_source）：
#   优先 HEALTH_URL_<CLUSTER 大写、下划线化>，其次全局 HEALTH_URL；都没有则返回 1。
#   注：集群 id 含 '-' 时不可直接做变量名（${HEALTH_URL_cluster-a:-} 会被 bash 误解析成 a:-），
#   故统一下划线化。
dr_health_url_of() {
  local cid="$1" key v1 v3 a c
  key="$(printf '%s' "$cid" | tr '[:lower:]-' '[:upper:]_')"
  v1="HEALTH_URL_${key}"
  v3="HEALTH_URL"
  eval "a=\"\${$v1:-}\"; c=\"\${$v3:-}\""
  if [ -n "$a" ]; then printf '%s' "$a"; return 0; fi
  if [ -n "$c" ]; then printf '%s' "$c"; return 0; fi
  return 1
}

# dr_http_code <url> [curl 额外参数...] → stdout 输出 HTTP 码（失败输出 000）
# ★ 健康源是**内网/集群内**地址：默认绕过 HTTP 代理（--noproxy '*'），
#   否则受控环境里的 http_proxy 会把探测转发出去并返回 502（假阴性）。
#   需要走代理时用 DR_HTTP_NOPROXY='' 关闭该行为。
dr_http_code() {
  local url="$1"; shift
  local code
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time "${DR_HTTP_TIMEOUT:-5}" \
    --noproxy "${DR_HTTP_NOPROXY-*}" "$@" "$url" 2>/dev/null)" || code="000"
  printf '%s' "$code"
}

# ---------- 人工确认（D-5 默认人工确认）----------
# dr_confirm <提示语> → 0 已确认 / 1 未确认
#   CONFIRM=1 环境变量或 stdin 输入 "yes" 视为确认；dry-run 下自动视为"待人工确认"并返回 1（记 dry-run）。
dr_confirm() {
  local prompt="$1"
  if [ "$DRY_RUN" = "1" ]; then
    dr_dryrun "confirm" "人工确认" "dry-run：$prompt（未真实征求确认）"
    return 1
  fi
  if [ "${CONFIRM:-0}" = "1" ]; then
    dr_pass "confirm" "人工确认" "CONFIRM=1（操作员已确认）：$prompt"
    return 0
  fi
  local ans=""
  printf '%s\n  输入 yes 继续，其它中止：' "$prompt"
  read -r ans || true
  if [ "$ans" = "yes" ]; then
    dr_pass "confirm" "人工确认" "操作员确认：$prompt"
    return 0
  fi
  dr_fail "confirm" "人工确认" "未获确认（输入='$ans'）：$prompt"
  return 1
}

# dr_confirm_gate <提示语> — 确认门禁：
#   · dry-run：只记录 dry-run 步骤，**不判失败**（预演无真实确认动作）
#   · 真实执行：未获确认 ⇒ 记 fail 并返回 1（由调用方决定退出码）
dr_confirm_gate() {
  if [ "$DRY_RUN" = "1" ]; then
    dr_confirm "$1" || true
    return 0
  fi
  dr_confirm "$1"
}

# dr_dryrun_dependent <id> <name> <detail> — 依赖"真实变更已发生"的断言的统一入口：
#   · dry-run ⇒ 记 dry-run 步骤并返回 0（该断言**无法**在不执行变更时成立，故不判失败）；
#   · 真实执行 ⇒ 返回 1，由调用方做实际断言。
dr_dryrun_dependent() {
  if [ "$DRY_RUN" = "1" ]; then
    dr_dryrun "$1" "$2" "$3"
    return 0
  fi
  return 1
}

# ---------- 证据产出 ----------
# dr_result_word_into —— 结论写入 DR_RESULT_WORD（纯 bash，不 fork）。
dr_result_word_into() {
  if [ "$DR_ENV_UNMET" -eq 1 ]; then DR_RESULT_WORD=env_unmet
  elif [ "$DR_FAILED" -eq 1 ]; then DR_RESULT_WORD=fail
  else DR_RESULT_WORD=pass; fi
}

dr_result_word() {
  dr_result_word_into
  printf '%s' "$DR_RESULT_WORD"
}

# dr_write_report [退出码]
#   产出 report.json（机器可读结论）。可重复调用：**最后一次写入生效**，
#   dr_finalize 会以最终退出码重写一次，保证报告里的 exit_code 与进程退出码一致。
dr_write_report() {
  local exit_code="${1:-${DR_EXIT_CODE:-0}}"
  local result dur_ms line first=1 inc_json="" executed
  dr_result_word_into
  result="$DR_RESULT_WORD"
  if [ "$DRY_RUN" = "1" ]; then executed=false; else executed=true; fi
  dur_ms=$(( $(dr_now_ms) - DR_START_MS ))
  # 异常列表：逐行转义后用逗号连接
  if [ -s "$DR_INCIDENTS_FILE" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      dr_json_escape_into "$line"
      if [ "$first" -eq 1 ]; then first=0; else inc_json="$inc_json,"; fi
      inc_json="$inc_json\"$DR_JSON_ESCAPED\""
    done < "$DR_INCIDENTS_FILE"
  fi
  dr_json_join_into "$DR_STEPS_FILE"
  dr_json_escape_into "$DRILL_TITLE"
  {
    printf '{'
    printf '"drill_id":"%s","title":"%s","generated_at":"%s",' \
      "$DRILL_ID" "$DR_JSON_ESCAPED" "$DR_RUN_TS"
    printf '"executed":%s,"result":"%s","exit_code":%d,"duration_ms":%d,' \
      "$executed" "$result" "$exit_code" "$dur_ms"
    printf '"rto_sec":%s,"rpo_sec":%s,' \
      "${DR_RTO_SEC:-null}" "${DR_RPO_SEC:-null}"
    printf '"steps":[%s],' "$DR_JSON_JOINED"
    printf '"incidents":[%s]' "$inc_json"
    printf '}\n'
  } > "$DR_EVIDENCE_DIR/report.json"
  DR_REPORT_WRITTEN=1
  DR_EXIT_CODE="$exit_code"
}

# dr_write_evidence_md <额外待人工补填项（Markdown 列表，可空）>
# 产出**证据骨架**：机器可填的（步骤/结果/时长/退出码）自动写入，人工项留 `TODO(人工)` 占位，
# 严禁由脚本代填主观结论。
dr_write_evidence_md() {
  local extra="${1:-}"
  local md="$DR_EVIDENCE_DIR/evidence.md"
  local line id name result detail obs_state rto_state rpo_state mode
  dr_result_word_into
  if [ "$DRY_RUN" = "1" ]; then mode='dry-run（只读预演，**不得作为验收证据**）'; else mode='真实执行'; fi
  if [ -n "${PROM_URL:-}" ]; then obs_state='自动采集'
  else obs_state='TODO(人工)：注入 PROM_URL 后重跑或手工粘贴'; fi
  if [ -n "$DR_RTO_SEC" ]; then rto_state="$DR_RTO_SEC 秒"; else rto_state='TODO(人工)'; fi
  if [ -n "$DR_RPO_SEC" ]; then rpo_state="$DR_RPO_SEC 秒"; else rpo_state='TODO(人工)'; fi
  {
    printf '# %s（%s）演练留证\n\n' "$DRILL_TITLE" "$DRILL_ID"
    printf -- '- 演练时间：%s\n' "$DR_RUN_TS"
    printf -- '- 执行模式：%s\n' "$mode"
    printf -- '- 结论：%s\n' "$DR_RESULT_WORD"
    printf -- '- 退出码：%s\n' "${DR_EXIT_CODE:-（见 report.json）}"
    printf -- '- 证据目录：%s\n\n' "$DR_EVIDENCE_DIR"
    printf '## 证据三要素（缺一不可）\n\n'
    printf '| 要素 | 内容 | 状态 |\n|---|---|---|\n'
    printf '| 时间窗 | 演练起止（见 report.json duration_ms / generated_at） | 自动记录 |\n'
    printf '| 操作记录 | 逐步操作与命令（见下方步骤表与 incidents） | 自动记录 |\n'
    printf '| 观测数据 | 指标/日志/探测输出（各步 detail；PROM_URL 等钩子注入后留档） | %s |\n\n' "$obs_state"
    printf '## 步骤\n\n'
    printf '| 步骤 | 名称 | 结果 | 详情 |\n|---|---|---|---|\n'
    if [ -f "$DR_STEPS_FILE" ]; then
      while IFS= read -r line || [ -n "$line" ]; do
        [ -n "$line" ] || continue
        dr_field_into "$line" id; id="$DR_FIELD"
        dr_field_into "$line" name; name="$DR_FIELD"
        dr_field_into "$line" result; result="$DR_FIELD"
        dr_field_into "$line" detail; detail="$DR_FIELD"
        printf '| %s | %s | %s | %s |\n' "$id" "$name" "$result" "$detail"
      done < "$DR_STEPS_FILE"
    fi
    printf '\n## RTO / RPO 实测登记\n\n'
    printf -- '- RTO：%s\n' "$rto_state"
    printf -- '- RPO：%s\n' "$rpo_state"
    printf '\n> 共享 PG 备份恢复 PITR 的 RTO/RPO **当前为占位**：客户书面确认前不得作为验收判据\n'
    printf '> （沿用 P2-3 口径）。\n\n'
    if [ -n "$extra" ]; then
      printf '## 本场景待人工补填项\n\n%s\n\n' "$extra"
    fi
    printf '## 异常（incidents）\n\n'
    if [ -s "$DR_INCIDENTS_FILE" ]; then
      while IFS= read -r line || [ -n "$line" ]; do
        printf -- '- %s\n' "$line"
      done < "$DR_INCIDENTS_FILE"
    else
      printf '（无）\n'
    fi
    printf '\n> 本文件由脚本生成骨架；所有 `TODO(人工)` 项须由演练执行人补齐后方可归档至\n'
    printf '> `docs/verify/multicluster/`（V-8 留证）。\n'
  } > "$md"
  printf '证据骨架：%s\n' "$md"
}

# ---------- finalize ----------
# dr_compute_exit_code [原始退出码] —— 计算最终退出码，写入 DR_FINAL_CODE（纯 bash，不 fork）。
#   优先级：① 主流程已显式给出的非零退出码（尊重它）→ ② 环境不满足(3) → ③ 存在失败步骤(1) → ④ 通过(0)。
dr_compute_exit_code() {
  local code="${1:-0}"
  if [ "$code" -ne 0 ]; then
    DR_FINAL_CODE="$code"
  elif [ "$DR_ENV_UNMET" -eq 1 ]; then
    DR_FINAL_CODE=$DR_EXIT_ENV
  elif [ "$DR_FAILED" -eq 1 ]; then
    DR_FINAL_CODE=$DR_EXIT_FAIL
  else
    DR_FINAL_CODE=$DR_EXIT_OK
  fi
  # 结论提示（只提示一次；主流程与 EXIT trap 都会调用本函数）
  if [ "$DR_EXIT_MSG_SHOWN" = "0" ]; then
    if [ "$DR_FINAL_CODE" = "$DR_EXIT_ENV" ]; then
      printf '环境前置不满足：本演练未真实执行，须环境就绪后重跑（退出码 3，非通过）。\n' >&2
      DR_EXIT_MSG_SHOWN=1
    elif [ "$DR_FINAL_CODE" = "$DR_EXIT_FAIL" ]; then
      printf '演练存在失败步骤（退出码 1）。\n' >&2
      DR_EXIT_MSG_SHOWN=1
    fi
  fi
}

# dr_finalize —— EXIT trap：**只做收尾（写报告），不改变已决定的退出状态**。
#
# ★ 口径：退出码由**主流程一处**决定（末尾 `dr_compute_exit_code $?; exit "$DR_FINAL_CODE"`），
#   本 trap 只负责把最终结论写进 report.json/evidence.md。
#   理由：① 在 EXIT trap 内调用 exit 在部分 shell 上会重入/递归（不可移植写法）；
#         ② 退出码只由一处决定 ⇒ 进程退出码与 report.json 的 exit_code **必然一致**。
dr_finalize() {
  local code=$?
  trap - EXIT
  dr_compute_exit_code "$code"
  dr_write_report "$DR_FINAL_CODE"
  dr_cleanup_tmp
  return 0
}
