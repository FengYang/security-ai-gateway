#!/usr/bin/env bash
# scripts/cryptop-drill.sh — P0-4 §13 国密切换演练编排器（B6#13，T-13.1）。
#
# 编排 §13.2 八步：
#   1 前置检查（capabilities 可达，profile == START_PROFILE，默认 intl）
#   2 intl 基线快照（capabilities 留档）
#   3 三段式切 sm-software：
#     3.1 服务端先行（→ sm + PRG=bridge，§13.2 步3.1）
#     3.2 插件侧已置 sm4 的结果验证（PLUGIN_PROBE_URL，带 X-OTPMask-MaskVersion: sm4 探活；
#         插件配置下发属外部系统，脚本只验结果；未给 = SKIP）
#     3.3 服务端 PRG=sm4 收桥（from==to 仅 PRG 变，T-12.6-5；§13.2 步3.3）
#   4 功能回归（DRILL_FUNCTION_CMD，未给 = SKIP）
#   5 双读验证（DRILL_DUALREAD_CMD，未给 = SKIP）
#   6 性能对比（DRILL_PERF_CMD，未给 = SKIP）
#   7 回滚（sm-software → intl + PRG=hmac-sha256；§13.2 步7 + R-14；未显式给 PRG 会被端点拒）
#   8 报告产出（DRILL-S2-<date>，§13.4）
#
# 退出码：0 完成（SKIP 不算失败；§13.3 量化结果进报告）；1 任一步骤失败；2 参数/初始化错误。
set -uo pipefail

ADMIN="${ADMIN:-http://127.0.0.1:8081}"
CRYPTOPSVC_URL="${CRYPTOPSVC_URL:-http://127.0.0.1:8082}"
START_PROFILE="${START_PROFILE:-intl}"
PLUGIN_PROBE_URL="${PLUGIN_PROBE_URL:-}"
DRILL_FUNCTION_CMD="${DRILL_FUNCTION_CMD:-}"
DRILL_DUALREAD_CMD="${DRILL_DUALREAD_CMD:-}"
DRILL_PERF_CMD="${DRILL_PERF_CMD:-}"
DRILL_OUT="${DRILL_OUT:-deploy/drill-runs}"

: "${ADMIN_TOKEN:?ADMIN_TOKEN 未设置（§4.3.10 端点强制 admin 鉴权）；用法: ADMIN_TOKEN=<token> bash scripts/cryptop-drill.sh}"
case "$START_PROFILE" in
  intl | sm-software | sm-module) ;;
  *) echo "START_PROFILE 非法: $START_PROFILE" >&2; exit 2 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_TS="$(date +%Y-%m-%dT%H-%M-%S)"
RUN_DATE="$(date +%Y-%m-%d)"
EVIDENCE_DIR="$DRILL_OUT/evidence/$RUN_TS"
STEPS_FILE="$(mktemp)"
SWITCH_FILE="$(mktemp)"
INCIDENTS_FILE="$(mktemp)"
REPORT_WRITTEN=0
DRILL_FAILED=0

cleanup_tmp() { rm -f "$STEPS_FILE" "$SWITCH_FILE" "$INCIDENTS_FILE"; }

# ---- JSON 辅助（所有外部文本经转义；detail 先 tr -d '\r'）----

json_escape() {
  local s="${1//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

add_step() {
  # $1 id $2 name $3 result $4 detail
  local detail
  detail="$(printf '%s' "$4" | tr -d '\r')"
  printf '{"id":"%s","name":"%s","result":"%s","detail":"%s"}\n' \
    "$1" "$2" "$3" "$(json_escape "$detail")" >> "$STEPS_FILE"
}

add_switch() {
  # $1 step $2 from $3 to $4 prg $5 result $6 duration_ms $7 detail
  local detail
  detail="$(printf '%s' "$7" | tr -d '\r')"
  printf '{"step":"%s","from":"%s","to":"%s","mask_prg":"%s","result":"%s","duration_ms":%d,"detail":"%s"}\n' \
    "$1" "$2" "$3" "$4" "$5" "$6" "$(json_escape "$detail")" >> "$SWITCH_FILE"
}

fail() {
  printf '%s' "$1" >> "$INCIDENTS_FILE"
  printf '%s\n' "$1" >&2
  DRILL_FAILED=1
}

json_join() { awk 'BEGIN{f=1}{if(!f)printf ",";printf "%s",$0;f=0}' "$1"; }

# ---- 能力快照提取 ----

fetch_capabilities() {
  curl -sS --max-time 3 "$CRYPTOPSVC_URL/v1/capabilities" 2>&1
}

field_of() { printf '%s' "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p"; }

# do_switch 调 §12.6 切换脚本：返回 "rc|duration_ms|output" 到 stdout。
do_switch() {
  # $1 from $2 to $3 prg
  local rc output dur start end
  start="$(date +%s%3N)"
  output="$(FROM="$1" TO="$2" PRG="$3" MODE=restart \
    ADMIN="$ADMIN" ADMIN_TOKEN="$ADMIN_TOKEN" CRYPTOPSVC_URL="$CRYPTOPSVC_URL" \
    bash "$SCRIPT_DIR/cryptop-switch-profile.sh" 2>&1)"
  rc=$?
  end="$(date +%s%3N)"
  dur=$((end - start))
  add_switch "$4" "$1" "$2" "$3" "$([ $rc -eq 0 ] && printf pass || printf fail)" "$dur" "$output"
  printf '%d|%d|%s' "$rc" "$dur" "$output"
}

# hook_step 执行环境注入命令钩子。
hook_step() {
  # $1 id $2 name $3 cmd
  local rc output
  if [ -z "$3" ]; then
    add_step "$1" "$2" skip "未注入 $1 命令（设环境变量 $1_CMD 在部署环境执行）"
    return
  fi
  output="$(bash -c "$3" 2>&1)"
  rc=$?
  if [ $rc -eq 0 ]; then
    add_step "$1" "$2" pass "$output"
  else
    add_step "$1" "$2" fail "$output"
    fail "步骤 $1 失败（exit $rc）"
  fi
}

# ---- 报告（失败也尽力产出，供证据分析）----

write_report() {
  mkdir -p "$EVIDENCE_DIR"
  local caps compliance incidents_json conclusion switch_phase
  caps="$1"
  compliance="$(field_of "$caps" compliance_note)"
  [ -z "$compliance" ] && compliance="（capabilities 未提供 compliance_note）"

  incidents_json="$(awk 'BEGIN{f=1}{if(!f)printf ",";printf "\""; gsub(/\\/,"\\\\"); gsub(/"/,"\\\""); printf "%s\"",$0;f=0}' "$INCIDENTS_FILE")"

  switch_phase="$2"

  {
    printf '{'
    printf '"report_id":"DRILL-S2-%s",' "$RUN_DATE"
    printf '"generated_at":"%s",' "$RUN_TS"
    printf '"environment":{"admin":"%s","sidecar":"%s","plugin_probe_url":"%s","start_profile":"%s"},' \
      "$ADMIN" "$CRYPTOPSVC_URL" "$PLUGIN_PROBE_URL" "$START_PROFILE"
    printf '"profile_switch_records":['
    json_join "$SWITCH_FILE"
    printf '],'
    printf '"switch_phase_seconds":%s,' "$switch_phase"
    printf '"steps":['
    json_join "$STEPS_FILE"
    printf '],'
    printf '"incidents":[%s],' "$incidents_json"
    printf '"compliance_note":"%s",' "$(json_escape "$compliance")"
    printf '"summary":{"result":"%s","incidents":%d},' \
      "$([ $DRILL_FAILED -eq 0 ] && printf pass || printf fail)" \
      "$(wc -l < "$INCIDENTS_FILE" | tr -d ' ')"
    if [ $DRILL_FAILED -eq 0 ]; then
      conclusion="演练完成：服务端先行(bridge)→插件 sm4 探活→服务端收桥(sm4)→回滚 intl；§13.3 结果以各步 detail 为准"
    else
      conclusion="演练存在失败步骤，见 incidents 与各步 detail；回滚状态以 profile_switch_records 末条为准"
    fi
    printf '"conclusion":"%s"' "$(json_escape "$conclusion")"
    printf '}\n'
  } > "$DRILL_OUT/drill-report.json"
  REPORT_WRITTEN=1
}

finalize() {
  local code=$?
  if [ "$REPORT_WRITTEN" -eq 0 ]; then
    local caps=""
    caps="$(fetch_capabilities 2>/dev/null || true)"
    write_report "$caps" "0"
  fi
  cleanup_tmp
  # 参数/初始化错误（exit 2）不翻转为 1。
  if [ "$code" -eq 2 ]; then exit 2; fi
  if [ "$DRILL_FAILED" -eq 1 ]; then exit 1; fi
  exit 0
}
trap finalize EXIT

# ====================== 演练主流程 ======================

mkdir -p "$EVIDENCE_DIR" || { echo "无法创建 $EVIDENCE_DIR" >&2; exit 2; }

# 1. 前置检查
caps="$(fetch_capabilities)" || {
  add_step "precheck" "前置检查" fail "sidecar 不可达：$caps"
  fail "前置检查失败：sidecar /v1/capabilities 不可达"
  exit 1
}
cur_profile="$(field_of "$caps" profile)"
cur_prg="$(field_of "$caps" mask_prg)"
if [ -z "$cur_profile" ]; then
  add_step "precheck" "前置检查" fail "capabilities 缺 profile：$caps"
  fail "前置检查失败：capabilities 响应缺 profile"
  exit 1
fi
if [ "$cur_profile" != "$START_PROFILE" ]; then
  add_step "precheck" "前置检查" fail "当前 profile=$cur_profile != START_PROFILE=$START_PROFILE"
  fail "前置检查失败：起点 profile 不符"
  exit 1
fi
add_step "precheck" "前置检查" pass "profile=$cur_profile mask_prg=$cur_prg"

# 2. 基线快照
printf '%s\n' "$caps" > "$EVIDENCE_DIR/baseline-capabilities.json"
add_step "baseline" "基线快照" pass "baseline 留档：$EVIDENCE_DIR/baseline-capabilities.json"

# 3.1 服务端先行
phase_start_ms="$(date +%s%3N)"
result="$(do_switch "$cur_profile" "sm-software" "bridge" "3.1")" || true
rc="${result%%|*}"; rest="${result#*|}"; switch_dur_31="${rest%%|*}"; switch_out_31="${rest#*|}"
if [ "$rc" -ne 0 ]; then
  add_step "3.1" "服务端先行升 sm(bridge)" fail "exit $rc：$switch_out_31"
  fail "3.1 切换失败"
fi
sm_reached=0
if [ "$rc" -eq 0 ]; then
  caps="$(fetch_capabilities)"
  np="$(field_of "$caps" profile)"; nprg="$(field_of "$caps" mask_prg)"
  if [ "$np" = "sm-software" ] && [ "$nprg" = "bridge" ]; then
    add_step "3.1" "服务端先行升 sm(bridge)" pass "profile=$np mask_prg=$nprg（${switch_dur_31}ms）"
    sm_reached=1
  else
    add_step "3.1" "服务端先行升 sm(bridge)" fail "切后实测 profile=$np mask_prg=$nprg"
    fail "3.1 切后状态不符"
  fi
fi

# 3.2 插件侧 sm4 结果验证
if [ "$sm_reached" -ne 1 ]; then
  add_step "3.2" "插件侧 sm4 探活" blocked "3.1 未成功"
else
  if [ -z "$PLUGIN_PROBE_URL" ]; then
    add_step "3.2" "插件侧 sm4 探活" skip "未注入 PLUGIN_PROBE_URL（插件配置下发属外部系统，部署环境验证）"
  else
    code="$(curl -sS -o "$EVIDENCE_DIR/plugin-probe.out" -w '%{http_code}' --max-time 3 \
      -H 'X-OTPMask-MaskVersion: sm4' "$PLUGIN_PROBE_URL" 2>&1)" || code="000"
    body="$(cat "$EVIDENCE_DIR/plugin-probe.out" 2>/dev/null || true)"
    case "$code" in
      2??)
        add_step "3.2" "插件侧 sm4 探活" pass "HTTP $code（X-OTPMask-MaskVersion: sm4）；$body" ;;
      *)
        add_step "3.2" "插件侧 sm4 探活" fail "HTTP $code；$body"
        fail "3.2 插件探活失败 HTTP $code" ;;
    esac
  fi
fi

# 3.3 服务端收桥
if [ "$sm_reached" -ne 1 ]; then
  add_step "3.3" "服务端 PRG=sm4 收桥" blocked "3.1 未成功"
  switch_phase_seconds="0"
else
  result="$(do_switch "sm-software" "sm-software" "sm4" "3.3")" || true
  rc="${result%%|*}"; rest="${result#*|}"; switch_dur_33="${rest%%|*}"; switch_out_33="${rest#*|}"
  caps="$(fetch_capabilities)"
  nprg="$(field_of "$caps" mask_prg)"
  if [ "$rc" -eq 0 ] && [ "$nprg" = "sm4" ]; then
    add_step "3.3" "服务端 PRG=sm4 收桥" pass "from==to 仅 mask_prg→sm4（T-12.6-5，${switch_dur_33}ms）"
  else
    add_step "3.3" "服务端 PRG=sm4 收桥" fail "exit $rc，实测 mask_prg=$nprg：$switch_out_33"
    fail "3.3 收桥失败"
  fi
  phase_end_ms="$(date +%s%3N)"
  switch_phase_seconds="$(awk "BEGIN{printf \"%.3f\", ($phase_end_ms-$phase_start_ms)/1000}")"
fi

# 4-6 功能/双读/性能（钩子，缺省 SKIP）
if [ "$sm_reached" -ne 1 ]; then
  add_step "4" "功能回归(E2E-02)" blocked "3.1 未成功"
  add_step "5" "双读验证(E2E-03)" blocked "3.1 未成功"
  add_step "6" "性能对比(§8)" blocked "3.1 未成功"
else
  hook_step "4" "功能回归(E2E-02)" "$DRILL_FUNCTION_CMD"
  hook_step "5" "双读验证(E2E-03)" "$DRILL_DUALREAD_CMD"
  hook_step "6" "性能对比(§8)" "$DRILL_PERF_CMD"
fi

# 7. 回滚（仅当前确为 sm-software 时执行）
caps="$(fetch_capabilities)"
cur_profile="$(field_of "$caps" profile)"
if [ "$cur_profile" = "sm-software" ]; then
  result="$(do_switch "sm-software" "intl" "hmac-sha256" "7")" || true
  rc="${result%%|*}"; rest="${result#*|}"; rb_dur="${rest%%|*}"; rb_out="${rest#*|}"
  caps="$(fetch_capabilities)"
  np="$(field_of "$caps" profile)"; nprg="$(field_of "$caps" mask_prg)"
  if [ "$rc" -eq 0 ] && [ "$np" = "intl" ] && [ "$nprg" = "hmac-sha256" ]; then
    add_step "7" "回滚 intl" pass "profile=intl mask_prg=hmac-sha256（${rb_dur}ms，无残留）"
  else
    add_step "7" "回滚 intl" fail "exit $rc，实测 profile=$np mask_prg=$nprg：$rb_out"
    fail "7 回滚失败或有残留"
  fi
else
  add_step "7" "回滚 intl" skip "当前 profile=$cur_profile（非 sm-software，无需回滚）"
fi

# 8. 报告
write_report "$caps" "$switch_phase_seconds"
printf '演练报告：%s\n' "$DRILL_OUT/drill-report.json"
