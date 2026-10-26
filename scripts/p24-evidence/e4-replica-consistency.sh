#!/usr/bin/env bash
# scripts/p24-evidence/e4-replica-consistency.sh
#
# ── 对应登记项 ────────────────────────────────────────────────────────────────
#   PRE-B-6：2 副本共享库一致性未实测
#     （replicas=2 + 共享库下 tenant 数据 / 登录失败锁定 / captcha 限流的**全局**一致性；
#       含 P2-1 裁决的"降级期间锁定强度按副本数放大"实测）
#
# ── 本脚本的边界（重要）───────────────────────────────────────────────────────
#   "一致性"不是看一眼 Pod 数就能断言的。脚本负责：
#     ① 钉住事实：副本数、两个副本是否真的指向同一个 PG、PG 不可达时的实际表现；
#     ② 编排并发探测：N 路并发打到不同副本，采集各自返回；
#     ③ 把必须由人判定的部分（锁定阈值折算是否成立、降级窗口内的体验）列成待填清单。
#   ★ 脚本**不**代替人工结论；没跑成一律 exit 3。
#
# ── 前置 ─────────────────────────────────────────────────────────────────────
#   --ctx <context>          目标集群 context（默认 current-context）
#   --svc <service/端口>     被探测的服务（如 gateway-admin-service:8085）
#   --path <探测路径>        默认 /healthz
#   --replicas <n>           期望副本数（默认 2）
#   --concurrency <n>        并发探测数（默认 20）
#   --kubeconfig <path>      可选
#
# ── 用法 ─────────────────────────────────────────────────────────────────────
#   ./e4-replica-consistency.sh --svc gateway-admin-service:8085 --path /healthz
#
# ── 退出码 ───────────────────────────────────────────────────────────────────
#   0 通过｜1 失败｜2 参数错误｜3 环境前置不满足

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_PRE_OUT="${DRILL_OUT:-}"
# shellcheck source=../drills/_lib.sh
source "$HERE/../drills/_lib.sh"

DRILL_ID="PRE-B-6-replica-consistency"
DRILL_TITLE="PRE-B-6 2 副本共享库一致性前置取证"
if [ -n "${_PRE_OUT:-}" ]; then DRILL_OUT="$_PRE_OUT"; else
  DRILL_OUT="$HERE/../../docs/verify/multicluster/evidence"
fi

CTX=""; SVC=""; PATH_P="/healthz"; EXP_REPL=2; CONC=20; KCFG=""
NEW_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --ctx)        CTX="${2:-}"; shift 2; continue ;;
    --svc)        SVC="${2:-}"; shift 2; continue ;;
    --path)       PATH_P="${2:-}"; shift 2; continue ;;
    --replicas)   EXP_REPL="${2:-2}"; shift 2; continue ;;
    --concurrency) CONC="${2:-20}"; shift 2; continue ;;
    --kubeconfig) KCFG="${2:-}"; shift 2; continue ;;
    -h|--help) sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  esac
  NEW_ARGS+=("$1"); shift
done
if [ ${#NEW_ARGS[@]} -gt 0 ]; then dr_parse_common "${NEW_ARGS[@]}"; else dr_parse_common; fi

KC_ARGS=""; [ -n "$KCFG" ] && KC_ARGS="--kubeconfig '$KCFG'"
CTX_ARG=""; [ -n "$CTX" ] && CTX_ARG="--context '$CTX'"
export KC_ARGS CTX_ARG SVC PATH_P CONC

dr_init
printf '== %s ==\n证据目录：%s\n服务：%s%s\n\n' "$DRILL_TITLE" "$DR_EVIDENCE_DIR" "${SVC:-(未给)}" "$PATH_P"

# ---------- ① 前置 ----------
command -v kubectl >/dev/null 2>&1 || { dr_step env "kubectl" env_unmet "未安装/不在 PATH"; DR_ENV_UNMET=1; }
[ -n "$SVC" ] || { dr_step env "探测目标" env_unmet "未给 --svc（形如 gateway-admin-service:8085）"; DR_ENV_UNMET=1; }
if [ "$DR_ENV_UNMET" = "1" ]; then dr_compute_exit_code 0; exit "$DR_FINAL_CODE"; fi

# ---------- ② 副本数与共享库指向（只读）----------
dr_exec_ro e4-replicas "admin-service 副本数（期望 $EXP_REPL）" \
  "kubectl \$KC_ARGS \$CTX_ARG -n otpmask get deploy gateway-admin-service -o jsonpath='{.spec.replicas}{\"\\n\"}{.status.readyReplicas}{\"\\n\"}'"
dr_exec_ro e4-pods "两个副本所在节点（用于印证非同一节点）" \
  "kubectl \$KC_ARGS \$CTX_ARG -n otpmask get pod -l app=gateway-admin-service -o wide"
# 只看"是否设置"，**不打印 DSN 值**（避免口令进证据）
dr_exec_ro e4-dsn-set "两个副本是否都指向共享 PG（仅打印是否设置）" \
  "kubectl \$KC_ARGS \$CTX_ARG -n otpmask get deploy gateway-admin-service -o jsonpath='{range .spec.template.spec.containers[*].env[*]}{.name}{'='}{.value}{'\\n'}{end}' | sed -E 's#(TENANT_STORE_PG_DSN)=.*#\\1=<已设置(值已脱敏)>#' | grep -E 'TENANT_STORE_PG_DSN|TENANT_STORE_PATH'"
dr_exec_ro e4-sqlite "SQLite 兜底是否已关闭（设了 PATH 就不是共享库）" \
  "kubectl \$KC_ARGS \$CTX_ARG -n otpmask get deploy gateway-admin-service -o jsonpath='{range .spec.template.spec.containers[*].env[*]}{.name}{\"\\n\"}{end}' | grep -c '^TENANT_STORE_PATH$'"

# ---------- ③ 并发探测（打到 service，由 kube-proxy 分散到两副本）----------
if command -v kubectl >/dev/null 2>&1; then
  dr_exec_ro e4-concurrent "$CONC 路并发探测（观察是否出现个别副本异常）" \
    "command -v curl >/dev/null 2>&1 || { echo 'no curl, skip'; exit 0; }
     port=\${SVC##*:}; host=\${SVC%%:*}
     kubectl \$KC_ARGS \$CTX_ARG -n otpmask port-forward svc/\$host \$port:\$port >/dev/null 2>&1 &
     pf=\$!; sleep 2
     i=0; while [ \$i -lt \$CONC ]; do
       curl -sS -o /dev/null -w '%{http_code}\\n' -m 5 \"http://127.0.0.1:\$port\$PATH_P\" &
       i=\$((i+1))
     done; wait
     kill \$pf 2>/dev/null"
else
  dr_skip e4-concurrent "并发探测" "无 kubectl"
fi

# ---------- ④ PG 不可达注入（有意识的选择：脚本不自动做）----------
dr_blocked e4-degrade "PG 不可达降级实测" \
  "**刻意不自动化**：断开共享库属于破坏性动作，须在演练窗口由人执行并计时（见待填项）。脚本只提供观测口径：锁定阈值应随副本数折算，降级期间不得静默放宽"

printf '\n完成（前置取证部分）。证据：%s\n' "$DR_EVIDENCE_DIR"
dr_write_evidence_md "\`PRE-B-6\` 降级窗口实测：注入方式（停 PG / 断网络策略）、开始与恢复时刻、锁定阈值在 1 副本与 2 副本下的实测折算比
租户数据一致性：同一 tenant 在两个副本分别读写后的可见性结果（含读己之写）
captcha / 限流全局一致性：N 路并发后的实际计数与期望上限对比
**以上三项未实测时写"未执行"，禁止以设计值代填**"
dr_compute_exit_code 0
exit "$DR_FINAL_CODE"
