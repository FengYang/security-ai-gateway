#!/usr/bin/env bash
# scripts/p24-evidence/e3-multicluster.sh
#
# ── 对应登记项 ────────────────────────────────────────────────────────────────
#   PRE-B-5：双集群联调未执行（真实双集群环境未就绪）→ V-4 整体阻塞
#
# ── 本脚本做两件事 ────────────────────────────────────────────────────────────
#   ① 把「双集群到底有没有就绪」变成**机器可判的事实**（两个 context 各自能否连、
#      节点/工作负载现状、两侧 cluster_id 是否已配），不再靠人回忆；
#   ② 若 registry API 尚未落地（PRE-A-14），明确判 blocked 并指向依赖，
#      **不假装"联调通过"**。
#
# ── 前置 ─────────────────────────────────────────────────────────────────────
#   --ctx-a <context> / --ctx-b <context>   两个集群的 kubectl context（用 KUBECONFIG 或 --kubeconfig）
#   --kubeconfig <path>                     可选：合并后的 kubeconfig
#   --registry <url>                        可选：registry API 地址（T-2.2 未落地时留空）
#   --token <bearer>                        可选：registry 认证
#
# ── 用法 ─────────────────────────────────────────────────────────────────────
#   ./e3-multicluster.sh --ctx-a k3s-a --ctx-b k3s-b
#   ./e3-multicluster.sh --ctx-a k3s-a --ctx-b k3s-b --registry http://10.0.0.10:8085 --token "$T"
#
# ── 退出码 ───────────────────────────────────────────────────────────────────
#   0 通过｜1 失败｜2 参数错误｜3 环境前置不满足（双集群/registry 不具备）

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_PRE_OUT="${DRILL_OUT:-}"
# shellcheck source=../drills/_lib.sh
source "$HERE/../drills/_lib.sh"

DRILL_ID="PRE-B-5-multicluster"
DRILL_TITLE="PRE-B-5 双集群联调前置取证"
if [ -n "${_PRE_OUT:-}" ]; then DRILL_OUT="$_PRE_OUT"; else
  DRILL_OUT="$HERE/../../docs/verify/multicluster/evidence"
fi

CTX_A=""; CTX_B=""; KCFG=""; REGISTRY=""; TOKEN=""
NEW_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --ctx-a)      CTX_A="${2:-}"; shift 2; continue ;;
    --ctx-b)      CTX_B="${2:-}"; shift 2; continue ;;
    --kubeconfig) KCFG="${2:-}"; shift 2; continue ;;
    --registry)   REGISTRY="${2:-}"; shift 2; continue ;;
    --token)      TOKEN="${2:-}"; shift 2; continue ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  esac
  NEW_ARGS+=("$1"); shift
done
if [ ${#NEW_ARGS[@]} -gt 0 ]; then dr_parse_common "${NEW_ARGS[@]}"; else dr_parse_common; fi

KC_ARGS=""
[ -n "$KCFG" ] && KC_ARGS="--kubeconfig '$KCFG'"
export KC_ARGS REGISTRY TOKEN

dr_init
printf '== %s ==\n证据目录：%s\nA=%s B=%s registry=%s\n\n' \
  "$DRILL_TITLE" "$DR_EVIDENCE_DIR" "${CTX_A:-(未给)}" "${CTX_B:-(未给)}" "${REGISTRY:-(未落地)}"

# ---------- ① 前置 ----------
if ! command -v kubectl >/dev/null 2>&1; then
  dr_step env "kubectl" env_unmet "未安装/不在 PATH"
  DR_ENV_UNMET=1
fi
if [ -z "$CTX_A" ] || [ -z "$CTX_B" ]; then
  dr_step env "双集群 context" env_unmet "需同时给 --ctx-a 与 --ctx-b；缺一即无法联调（PRE-B-5 未解除）"
  DR_ENV_UNMET=1
fi
if [ "$DR_ENV_UNMET" = "1" ]; then
  dr_compute_exit_code 0; exit "$DR_FINAL_CODE"
fi

# ---------- ② 两集群各自可达性与现状（只读）----------
probe_cluster() {
  local ctx="$1" label="$2"
  dr_exec_ro "e3-$label-info" "$label cluster-info" \
    "kubectl $KC_ARGS --context '$ctx' cluster-info 2>&1 | head -3"
  dr_exec_ro "e3-$label-nodes" "$label 节点" \
    "kubectl $KC_ARGS --context '$ctx' get nodes -o wide"
  dr_exec_ro "e3-$label-otpmask" "$label otpmask 命名空间工作负载" \
    "kubectl $KC_ARGS --context '$ctx' -n otpmask get deploy,sts,pod -o wide 2>&1 | head -40"
  # cluster 标签是中央侧聚合的唯一来源，两侧都必须配
  dr_exec_ro "e3-$label-clusterlabel" "$label external_labels.cluster（漏配 → 中央 cluster='')" \
    "kubectl $KC_ARGS --context '$ctx' -n otpmask get cm prometheus -o jsonpath='{.data.prometheus\\.yml}' 2>/dev/null | grep -A2 external_labels | head -6"
}
probe_cluster "$CTX_A" a
probe_cluster "$CTX_B" b

# ---------- ③ registry API（T-2.2 是否落地）----------
if [ -z "$REGISTRY" ]; then
  dr_blocked e3-registry "registry 注册/心跳" \
    "未给 --registry：T-2.2 路由是否已注册需先确认（PRE-A-14）。此状态下 V-2/V-4 的采集路径无法固定 → 联调结论不得写通过"
else
  if command -v curl >/dev/null 2>&1; then
    dr_exec_ro e3-registry "registry 集群列表" \
      "curl -sS -m 8 -H 'Authorization: Bearer \"\$TOKEN\"' \"\$REGISTRY/v1/clusters\" | head -c 2000"
    # 心跳：连续采样 3 次，看 last_heartbeat 是否推进（推进 = 心跳链路通）
    dr_exec_ro e3-heartbeat "心跳推进采样（3 次，间隔 5s）" \
      "for i in 1 2 3; do date +%H:%M:%S; curl -sS -m 8 -H 'Authorization: Bearer \"\$TOKEN\"' \"\$REGISTRY/v1/clusters\" | head -c 600; echo; sleep 5; done"
  else
    dr_skip e3-registry "registry 探测" "无 curl"
  fi
fi

printf '\n完成（前置取证部分）。证据：%s\n' "$DR_EVIDENCE_DIR"
dr_write_evidence_md "\`PRE-B-5\` 两集群注册结果（cluster_id / 状态 / 审批人），以及心跳最后一次上报时间
\`V-4\` 跨集群按 cluster 维度查询：查到的集群数、样本时间范围、与两侧 Prometheus 本地数据的量级对比
若本脚本 ② 步任一集群连不上：写明是节点离线、证书过期还是网络不通（**不得写"环境不具备"了事**）"
dr_compute_exit_code 0
exit "$DR_FINAL_CODE"
