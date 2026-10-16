#!/usr/bin/env bash
# P1-7 T11（本体 §7.10）：审计性能基线压测脚本（V-10 过程留证）。
#
# 目标（本体 §7.10 T11）：量化留痕与归档对在线推理的影响，形成**可复算**基准。
#   ① 固定并发/时长跑两轮——`-audit-file` 开/关；
#   ② 采集 p50/p99、写入吞吐、归档迁移耗时；
#   ③ 与基线（noworm）比对出**增量**；
#   ④ 报告附压测参数与原始数据。
# 验收 V-10：**p99 增量 < 3%**（fsync 档位与采集器占用须记录于报告，A4-11）。
#
# 用法：
#   scripts/audit-baseline.sh mode-a [OUTDIR]
#       —— 进程内写入基准（Go benchmark + 分位测量），**无需部署**，可复算。
#          覆盖「写入吞吐 / 归档迁移耗时 / 进程内分位」。
#   scripts/audit-baseline.sh mode-b [OUTDIR]
#       —— e2e 两轮压测（`-audit-file` 开/关，hey/wrk 打推理端点），需 tee-infer
#          已部署且本机/CI 有 hey（或 wrk）。覆盖「端到端 p50/p99 与增量」= V-10 正式判据。
#
# 环境要求：
#   - Go ≥ 1.26（go.mod 要求；本机 Go <1.26 时请改用 K3s 编译机 /root/sag）
#   - mode-b 另需 hey（`go install github.com/rakyll/hey@latest`）或 wrk
#
# 环境变量：
#   BENCHTIME   模式 A 的 -benchtime（默认 2s）
#   BASE_URL    模式 B 服务地址（默认 http://127.0.0.1:19090）
#   ENDPOINT    模式 B 压测端点（默认 /infer）
#   BODY_FILE   模式 B 请求体文件（**须为合法 c2s 加密信封**，见下）
#   CONC/DUR/N 模式 B 并发/时长/请求数（默认 50 / 30s / 100000）
#
# ⚠️ 请求体说明：tee-infer 的推理入口（P1c）要求 c2s 加密信封（fail-closed，防降级攻击），
#    裸 JSON 会被拒（不会走到留痕路径）。合法信封构造：先 POST /attest/complete 建立会话，
#    再用协商密钥加密请求体；可复用 tmp_e2e_*.py 的既有实现，或由 T12 安全测试用例提供。
#    若仅验证「留痕开/关」对比，也可压测任意**会落链**的端点（如 /audit/report，需 HMAC）。

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG="./gateway/tee-infer-service/"
MODE="${1:-mode-a}"
OUTDIR="${2:-$REPO_ROOT/deploy/audit/perf}"
STAMP="$(date +%Y%m%d-%H%M%S)"
BENCHTIME="${BENCHTIME:-2s}"
BASE_URL="${BASE_URL:-http://127.0.0.1:19090}"
ENDPOINT="${ENDPOINT:-/infer}"
CONC="${CONC:-50}"
DUR="${DUR:-30s}"
N="${N:-100000}"

mkdir -p "$OUTDIR"
REPORT="$OUTDIR/P1-7-audit-baseline-$STAMP.md"
RAW_BENCH="$OUTDIR/bench-$STAMP.txt"
RAW_LAT="$OUTDIR/latency-$STAMP.txt"
RAW_E2E_A="$OUTDIR/e2e-audit-off-$STAMP.txt"
RAW_E2E_B="$OUTDIR/e2e-audit-on-$STAMP.txt"

log() { printf '[audit-baseline] %s\n' "$*"; }

check_go() {
  command -v go >/dev/null 2>&1 || { log "缺少 go（需 ≥1.26；本机不足时请用 K3s /root/sag）"; exit 1; }
  local v major minor
  v="$(go version | awk '{print $3}' | sed 's/^go//')"
  major="${v%%.*}"; minor="${v#*.}"; minor="${minor%%.*}"
  if [ "$major" -lt 1 ] || { [ "$major" -eq 1 ] && [ "$minor" -lt 26 ]; }; then
    log "go $v < 1.26（go.mod 要求）；请改用 K3s 编译机"; exit 1
  fi
  log "go $v 就绪"
}

collect_env() {
  {
    echo "- 时间：$(date -Is)"
    echo "- Go：$(go version 2>/dev/null || echo 'n/a')"
    echo "- 主机：$(uname -srm 2>/dev/null || echo n/a)"
    echo "- CPU：$(nproc 2>/dev/null || echo n/a) 核"
    echo "- 内核/存储：$( [ -f /proc/version ] && head -1 /proc/version || echo n/a )"
  } >>"$REPORT"
}

mode_a() {
  log "模式 A：进程内写入基准（无需部署）"
  check_go
  cd "$REPO_ROOT"
  {
    echo "# P1-7 审计性能基线（T11 · 模式 A 进程内写入）"
    echo
    echo "> 由 scripts/audit-baseline.sh 于 $STAMP 生成；可复算："
    echo "> \`go test -bench BenchmarkAudit -benchmem -benchtime=$BENCHTIME $PKG\`"
    echo "> \`AUDIT_PERF=1 go test -run TestAuditWriteLatencyP99 -v $PKG\`"
    echo
    echo "## 环境"
  } >"$REPORT"
  collect_env

  log "运行 benchmark（三档 + 归档 sink）…"
  go test -bench 'BenchmarkAudit' -benchmem -benchtime="$BENCHTIME" -run '^$' "$PKG" 2>&1 | tee "$RAW_BENCH"

  log "运行分位测量（AUDIT_PERF=1）…"
  AUDIT_PERF=1 go test -run TestAuditWriteLatencyP99 -v "$PKG" 2>&1 | tee "$RAW_LAT"

  {
    echo
    echo "## 写入吞吐（Go benchmark，ns/op 与 B/op）"
    echo '```'
    grep -E '^Benchmark' "$RAW_BENCH"
    echo '```'
    echo
    echo "## 分位（进程内；**非** e2e p99）"
    echo '```'
    grep -E '^\| ' "$RAW_LAT" || sed -n '/T11 审计写入分位/,/注：/p' "$RAW_LAT"
    echo '```'
    echo
    echo "## 结论与后续"
    echo
    echo "- 本模式给出**写入路径**（hash + WORM 落盘）的可复算分位与吞吐，是 e2e 劣化归因的分解依据。"
    echo "- **V-10（p99 增量 <3%）的正式判定须以模式 B（e2e 两轮）为准**。"
    echo "- 若 batch 档劣化显著：核对 -audit-fsync 档位是否误配为 per_event（D-17）。"
    echo "- 归档迁移耗时：benchmark 的 BenchmarkAuditArchiveSinkWrite 为本地 FS sink 速率；"
    echo "  对象存储 sink 须部署态实测（并计入 T2c 采集器资源占用，A4-11）。"
  } >>"$REPORT"
  log "报告：$REPORT"
}

mode_b() {
  log "模式 B：e2e 两轮（-audit-file 开/关）"
  if ! command -v hey >/dev/null 2>&1 && ! command -v wrk >/dev/null 2>&1; then
    log "未找到 hey/wrk。安装：go install github.com/rakyll/hey@latest"
    log "（或改用 wrk；命令模板见报告）"
  fi
  local body_args=()
  if [ -n "${BODY_FILE:-}" ]; then
    [ -f "$BODY_FILE" ] || { log "BODY_FILE 不存在：$BODY_FILE"; exit 1; }
    body_args=(-D "$BODY_FILE" -T "application/json")
    log "使用请求体：$BODY_FILE"
  else
    log "⚠️ 未提供 BODY_FILE：推理入口需合法 c2s 信封（见脚本头说明），裸 JSON 将被拒。"
  fi

  {
    echo "# P1-7 审计性能基线（T11 · 模式 B e2e 两轮）"
    echo
    echo "## 压测参数"
    echo
    echo "- 地址：$BASE_URL  端点：$ENDPOINT  并发：$CONC  时长：$DUR  请求数：$N"
    echo "- 轮①：服务**不带** -audit-file（内存模式，基线）"
    echo "- 轮②：服务带 -audit-file（WORM，默认 batch 档）"
    echo "- 时间：$(date -Is)"
    echo
    echo "## 原始输出"
  } >"$REPORT"
  collect_env

  if command -v hey >/dev/null 2>&1; then
    log "轮①（audit off）… 请确认服务以内存模式运行"
    hey -z "$DUR" -c "$CONC" -m POST "${body_args[@]}" "$BASE_URL$ENDPOINT" 2>&1 | tee "$RAW_E2E_A" || log "轮① 执行失败（检查服务/请求体）"
    log "轮②（audit on）… 请重启服务并加 -audit-file 后重跑同一命令"
    log "  命令：hey -z $DUR -c $CONC -m POST${BODY_FILE:+ -D $BODY_FILE -T application/json} $BASE_URL$ENDPOINT | tee $RAW_E2E_B"
  elif command -v wrk >/dev/null 2>&1; then
    log "wrk：wrk -t$CONC -c$CONC -d$DUR -s <lua> $BASE_URL$ENDPOINT（两轮同上）"
  fi

  {
    echo '```'
    [ -s "$RAW_E2E_A" ] && cat "$RAW_E2E_A"
    echo '```'
    echo
    echo "## 增量计算（人工比对两轮 p50/p99）"
    echo
    echo "- 轮①（audit off）与轮②（audit on）的 p99 之差 / 轮① = 增量；**V-10 要求 < 3%**。"
    echo "- 若劣化 >3%：先用模式 A 分解（落盘 vs 哈希），再核对 fsync 档位（D-17）与"
    echo "  归档/采集器资源争抢（A4-11：Fluent Bit 不得与网关同机争抢资源，其 CPU/内存计入判定）。"
    echo "- 归档迁移耗时：观察归档器日志或对象存储 sink 写入速率（部署态）。"
  } >>"$REPORT"
  log "报告：$REPORT"
}

case "$MODE" in
  mode-a) mode_a ;;
  mode-b) mode_b ;;
  *) echo "用法: $0 mode-a|mode-b [OUTDIR]" >&2; exit 2 ;;
esac
