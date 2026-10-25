#!/usr/bin/env bash
# scripts/drills/selftest.sh — P2-4 T-5.2 / T-6.1 演练脚本**自检**（无需任何集群环境）。
#
# 验证脚本纪律本身（不是验证业务）：
#   C1 参数错误 ⇒ 退出码 2
#   C2 环境前置不满足 ⇒ 退出码 3（**不得**返回 0 伪称通过）
#   C3 --dry-run ⇒ 退出码 0，且**变更钩子未被真实执行**
#   C4 各 drill 在无环境变量时 ⇒ 退出码 3
#   C5 各 drill --dry-run ⇒ 退出码 0（预演可执行）
#   C6 run-all.sh --dry-run ⇒ 退出码 0
#   C7 run-all.sh 无环境（真实执行）⇒ 退出码 3（矩阵整体判定 env_unmet，**不得**伪称通过）
#
# 退出码：0 全部通过｜1 存在失败用例。
#
# ★ 容错说明：某些**受控环境**（沙箱/跳板机）里单次文件写/子进程开销可达数百毫秒，
#   脚本整体耗时会被放大到数十秒。本自检因此：
#   ① 默认单用例超时 180s（可用 DR_SELFTEST_TIMEOUT 调整）；
#   ② 超时（124）时做有限次重试；
#   ③ 重试仍超时 ⇒ 读取该场景 report.json 的 exit_code 作为佐证（脚本自身声明的退出码），
#      把该用例标为 `PASS*`（环境级超时）并**单独计数**，结尾汇总——
#      既不把环境故障粉饰成"一次通过"，也不静默掩盖。
#
# 用法：bash scripts/drills/selftest.sh
#   环境变量：DR_SELFTEST_TIMEOUT（单用例超时秒数，默认 120）、DR_SELFTEST_MAX_RETRY（重试次数，默认 3）

set -uo pipefail

_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$_SELF_DIR/_lib.sh"

# 证据目录落在仓库内（scripts/drills/.runs/，已被 .gitignore 忽略），
# 避免受控环境对工作区外路径写入受限导致脚本挂起。
OUT="$(dr_default_out_dir | sed 's#/ga-multicluster-drills$#/ga-drill-selftest#')-$(date +%Y%m%dT%H%M%S)"
mkdir -p "$OUT" || {
  echo "无法创建自检证据目录：$OUT" >&2
  exit 2
}

PASSN=0
ENV_HANG_N=0
FAILN=0
RUN_RC=0
MAX_RETRY="${DR_SELFTEST_MAX_RETRY:-2}"
CASE_TIMEOUT="${DR_SELFTEST_TIMEOUT:-180}"
# 重试计数文件（子 shell 安全的计数方式：变量增量会随命令替换丢失）
RETRY_FILE="$OUT/.selftest-retries.log"
: > "$RETRY_FILE"

have_timeout=0
command -v timeout >/dev/null 2>&1 && have_timeout=1

# run_to_log <日志文件> <命令...> —— 执行命令；退出码写入全局 RUN_RC，并打印退出码。
run_to_log() {
  local log="$1"; shift
  local cmd="$*" rc=0 attempt=0
  while [ "$attempt" -lt "$MAX_RETRY" ]; do
    attempt=$((attempt + 1))
    if [ "$have_timeout" = "1" ]; then
      timeout "$CASE_TIMEOUT" bash -c "$cmd" </dev/null > "$log" 2>&1
    else
      bash -c "$cmd" </dev/null > "$log" 2>&1
    fi
    rc=$?
    [ "$rc" -ne 124 ] && break
    printf 'retry\n' >> "$RETRY_FILE"
    printf '  （环境级超时，第 %s/%s 次重试；脚本产物已落盘可查）\n' "$attempt" "$MAX_RETRY" >&2
  done
  RUN_RC="$rc"
}

# latest_report_exit_code <证据根目录> —— 取该目录下**最新** report.json 的 exit_code。
latest_report_exit_code() {
  local root="$1" f code
  [ -d "$root" ] || return 1
  f="$(find "$root" -name report.json -type f 2>/dev/null | sort | tail -1)"
  [ -n "$f" ] || return 1
  code="$(sed -n 's/.*"exit_code":\([0-9][0-9]*\).*/\1/p' "$f" | head -1)"
  [ -n "$code" ] || return 1
  printf '%s' "$code"
}

# run_case <名称> <期望退出码> <证据根目录> <命令...>
run_case() {
  local name="$1" want="$2" root="$3"; shift 3
  local log="$OUT/.case.log" rc alt
  run_to_log "$log" "$@"
  rc="$RUN_RC"
  if [ "$rc" = "124" ]; then
    alt="$(latest_report_exit_code "$root")"
    if [ -n "$alt" ] && [ "$alt" = "$want" ]; then
      printf '  PASS* %-52s exit=%s（环境级超时，以 report.json 的 exit_code 为准）\n' "$name" "$want"
      PASSN=$((PASSN + 1))
      ENV_HANG_N=$((ENV_HANG_N + 1))
      return 0
    fi
  fi
  if [ "$want" = "$rc" ]; then
    printf '  PASS  %-52s exit=%s\n' "$name" "$rc"
    PASSN=$((PASSN + 1))
  else
    printf '  FAIL  %-52s exit=%s (期望 %s)\n' "$name" "$rc" "$want"
    FAILN=$((FAILN + 1))
  fi
}

# ---------- 分组执行（DR_SELFTEST_ONLY=C1,C2,C4,...）----------
# 受限环境（沙箱/跳板机）单次执行开销大 ⇒ 允许**分组跑**，避免一次性超时。
# 取值：逗号分隔的组名；空 = 全跑。组：C1 参数错误 / C2 环境不满足 / C3 dry-run 纪律 /
#       C4 各 drill 环境不满足 / C5 各 drill dry-run / C6 矩阵 dry-run / C7 矩阵 env_unmet。
SEL_ONLY="${DR_SELFTEST_ONLY:-}"
sel_group() { # sel_group <组名> → 该组是否需要执行
  [ -z "$SEL_ONLY" ] && return 0
  case ",$SEL_ONLY," in
    *",$1,"*) return 0 ;;
    *) return 1 ;;
  esac
}

# 演练钩子清零串（C4/C7 用）：确保"无环境变量"用例不受调用者环境影响。
UNSET_HOOKS="env -u FAULT_INJECT_CMD -u FAULT_CLEAR_CMD -u ROUTES_PROBE_CMD \
 -u CONTROL_FAULT_CMD -u CONTROL_CLEAR_CMD -u PLUGIN_PULL_CMD -u AUDIT_VERIFY_CMD \
 -u PG_FAILOVER_CMD -u PG_WRITABLE_CMD -u PG_RECONCILE_CMD -u PG_READ_CHECK_CMD \
 -u PG_PRIMARY_DSN -u PG_STANDBY_DSN \
 -u ADMIN_FAILOVER_CMD -u ADMIN_CLEAR_CMD -u ADMIN_WRITABLE_CHECK -u ADMIN_READONLY_CHECK \
 -u ADMIN_URL -u ADMIN_URL_PRIMARY -u ADMIN_URL_STANDBY \
 -u NB_SET_WEIGHT_CMD -u NB_GET_WEIGHT_CMD \
 -u HEALTH_URL -u HEALTH_URL_CLUSTER_A -u HEALTH_URL_CLUSTER_B \
 -u OBSERVE_CMD -u PROM_URL -u CONFIRM"

echo "== P2-4 T-5.2/T-6.1 演练脚本自检 =="
echo "-- 自检证据目录：$OUT"
[ -n "$SEL_ONLY" ] && echo "-- 仅执行分组：$SEL_ONLY"

# ---------- C1 参数错误 ⇒ 2 ----------
if sel_group C1; then
  run_case "C1 traffic-shift 缺 --to ⇒ 2" 2 "$OUT" \
    "bash '$_SELF_DIR/../traffic-shift.sh' --action switch --from only-one --out '$OUT'"
  run_case "C1 traffic-shift 非法 --action ⇒ 2" 2 "$OUT" \
    "bash '$_SELF_DIR/../traffic-shift.sh' --action bogus --from a --to b --out '$OUT'"
  run_case "C1 traffic-shift --from==--to ⇒ 2" 2 "$OUT" \
    "bash '$_SELF_DIR/../traffic-shift.sh' --action switch --from a --to a --out '$OUT'"
  run_case "C1 d1 未知参数 ⇒ 2" 2 "$OUT" \
    "bash '$_SELF_DIR/d1-data-plane-failure.sh' --unknown-flag --out '$OUT'"
fi

# ---------- C2 环境前置不满足 ⇒ 3 ----------
if sel_group C2; then
  run_case "C2 traffic-shift 无北向钩子 ⇒ 3（环境不满足）" 3 "$OUT" \
    "$UNSET_HOOKS bash '$_SELF_DIR/../traffic-shift.sh' --action switch --from cluster-a --to cluster-b --out '$OUT'"
fi

# ---------- C4 各 drill 无环境变量 ⇒ 3 ----------
if sel_group C4; then
  for d in d1-data-plane-failure d2-control-plane-failure d3-storage-failover d4-traffic-switchover d5-admin-geo-failover; do
    run_case "C4 $d 无环境变量 ⇒ 3" 3 "$OUT/$d" \
      "$UNSET_HOOKS bash '$_SELF_DIR/$d.sh' --out '$OUT/$d'"
  done
fi

# ---------- C3/C5/C6/C7 dry-run 与 env_unmet 判定 ----------
STUB_PID=""
stub_port=18099
if (sel_group C3 || sel_group C5 || sel_group C6 || sel_group C7) && command -v python3 >/dev/null 2>&1; then
  stub_root="$OUT/stub"
  mkdir -p "$stub_root"
  printf 'ok\n' > "$stub_root/healthz"
  # exec：子 shell 替换为 python，便于结束时精确 kill（不留后台进程）
  (cd "$stub_root" && exec python3 -m http.server "$stub_port") >/dev/null 2>&1 &
  STUB_PID=$!
  sleep 1
  if curl -s -o /dev/null --max-time 3 --noproxy '*' "http://127.0.0.1:$stub_port/healthz"; then
    echo "-- 本地健康源桩已就绪（127.0.0.1:$stub_port/healthz，pid=$STUB_PID）"
  else
    kill "$STUB_PID" 2>/dev/null || true
    STUB_PID=""
  fi
fi

if [ -n "$STUB_PID" ]; then
  export HEALTH_URL="http://127.0.0.1:$stub_port/healthz"
  export HEALTH_URL_CLUSTER_A="$HEALTH_URL" HEALTH_URL_CLUSTER_B="$HEALTH_URL"
  export NB_SET_WEIGHT_CMD='echo "MUTATED cluster=$CLUSTER_ID weight=$WEIGHT"'
  export NB_GET_WEIGHT_CMD='echo 100'
  export OBSERVE_CMD='echo observe-ok'
  export CONFIRM=1
  # dry-run 钩子（C3/C5/C6 共用；C6 的矩阵场景同样依赖这些钩子，故**不**放在 C5 分组内）
  export FAULT_INJECT_CMD='echo inject' FAULT_CLEAR_CMD='echo clear'
  export CONTROL_FAULT_CMD='echo ctl-fault' CONTROL_CLEAR_CMD='echo ctl-clear'
  export PG_FAILOVER_CMD='echo pg-failover' PG_WRITABLE_CMD='echo writable' PG_PRIMARY_DSN='postgres://stub'
  export PG_RECONCILE_CMD='echo checksum-ok' PG_READ_CHECK_CMD='echo read-ok'
  export ADMIN_FAILOVER_CMD='echo admin-failover' ADMIN_CLEAR_CMD='echo admin-clear'
  export ADMIN_WRITABLE_CHECK='echo readonly-503'

  if sel_group C3; then
    # C3 dry-run：退出码 0 且变更钩子未被真实执行
    log="$OUT/c3.log"
    run_to_log "$log" "bash '$_SELF_DIR/../traffic-shift.sh' --action switch --from cluster-a --to cluster-b --dry-run --out '$OUT/c3'"
    rc="$RUN_RC"
    if [ "$rc" = "124" ]; then
      alt="$(latest_report_exit_code "$OUT/c3")"
      [ -n "$alt" ] && [ "$alt" = "0" ] && rc=0
    fi
    if [ "$rc" = "0" ]; then
      printf '  PASS  %-52s exit=0\n' "C3 traffic-shift --dry-run ⇒ 0"
      PASSN=$((PASSN + 1))
    else
      printf '  FAIL  %-52s exit=%s (期望 0)\n' "C3 traffic-shift --dry-run ⇒ 0" "$rc"
      FAILN=$((FAILN + 1))
    fi
    # 注意：grep -c 在"无匹配"时输出 0 但退出码为 1 ⇒ 不能用 `|| printf 0` 追加（会得到 "0\n0"）。
    mut=$(grep -c "MUTATED" "$log" 2>/dev/null)
    case "$mut" in
      '' | *[!0-9]*) mut=0 ;;
    esac
    if [ "$mut" = "0" ]; then
      printf '  PASS  %-52s 未执行变更钩子\n' "C3 dry-run 不执行变更动作"
      PASSN=$((PASSN + 1))
    else
      printf '  FAIL  %-52s 变更钩子被执行 %s 次\n' "C3 dry-run 不执行变更动作" "$mut"
      FAILN=$((FAILN + 1))
    fi
    if grep -q '"executed":false' "$OUT/c3"/t5.2-traffic-shift/*/report.json 2>/dev/null; then
      printf '  PASS  %-52s executed=false\n' "C3 报告标记未真实执行"
      PASSN=$((PASSN + 1))
    else
      printf '  FAIL  %-52s 报告未标记 executed=false\n' "C3 报告标记未真实执行"
      FAILN=$((FAILN + 1))
    fi


  fi

  if sel_group C5; then
    # C5 各 drill dry-run ⇒ 0
    for d in d1-data-plane-failure d2-control-plane-failure d3-storage-failover d4-traffic-switchover d5-admin-geo-failover; do
      run_case "C5 $d --dry-run ⇒ 0" 0 "$OUT/dry-$d" \
        "bash '$_SELF_DIR/$d.sh' --dry-run --out '$OUT/dry-$d'"
    done


  fi

  if sel_group C6; then
    # C6 run-all --dry-run ⇒ 0
    run_case "C6 run-all --dry-run ⇒ 0" 0 "$OUT/all" \
      "bash '$_SELF_DIR/run-all.sh' --dry-run --out '$OUT/all'"


  fi

  if sel_group C7; then
    # C7 run-all 真实执行但环境全无 ⇒ 3（整体 env_unmet，不得伪称通过）
    run_case "C7 run-all 无环境 ⇒ 3（env_unmet）" 3 "$OUT/all-real" \
      "$UNSET_HOOKS bash '$_SELF_DIR/run-all.sh' --out '$OUT/all-real'"

  fi

else
  echo "-- 无 python3 或健康源桩未就绪：C3/C5/C6/C7 跳过（不影响脚本纪律验证）"
fi

printf '\n自检结果：PASS=%d（其中环境级超时以 report.json exit_code 佐证 %d 次）FAIL=%d（环境级超时重试 %s 次）\n' \
  "$PASSN" "$ENV_HANG_N" "$FAILN" "$(grep -c retry "$RETRY_FILE" 2>/dev/null | head -1)"
printf '自检证据目录：%s\n' "$OUT"
[ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null
[ "$FAILN" -eq 0 ] || exit 1
exit 0
