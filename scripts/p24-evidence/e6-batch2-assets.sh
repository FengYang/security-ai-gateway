#!/usr/bin/env bash
# scripts/p24-evidence/e6-batch2-assets.sh
#
# ── 对应登记项 ────────────────────────────────────────────────────────────────
#   PRE-B-9：批二资产真机取证（3 项）
#     ① NetworkPolicy 三档未在真 K8s apply（deploy/k8s-overlays/trust/networkpolicy-tiers/）
#     ② 四种接收端未做真实连通（deploy/monitoring/central/receivers/）
#     ③ 证书未做 K8s Secret 卷挂载验证（defaultMode 0400/0440 下非 root 能否读）
#
# ── 三项分别怎么测（本脚本各实现一段）────────────────────────────────────────
#   ① apply 一档 → 用临时 Pod 探测"应通/应断" → delete 该档。**必须回滚**，
#      三档是加性策略，残留会污染后续所有网络判断。
#   ② 对每个 --receiver URL 发一次最小 remote_write 请求，记录 HTTP 码；
#      Mimir 的「缺 X-Scope-OrgID 即拒」用"故意不带租户头"的一组来验证。
#   ③ 建临时 Secret → 挂进以 65534 运行的 Pod（fsGroup 也设 65534）→ 尝试读私钥，
#      分别测 0440 与 0400，得出**现场真实可用**的 defaultMode（这是 PRE-A-11 要的答案）。
#
# ── 前置 ─────────────────────────────────────────────────────────────────────
#   --ns <namespace>        默认 otpmask
#   --tier 1|2|3|all        只测指定档（默认跳过，显式给才测）
#   --probe-svc <host:port> NP 探测目标（默认 gateway-core:8085）
#   --probe-path <path>     默认 /healthz
#   --receiver <url>        可重复；接收端写入地址（不含 /api/v1/write 时自动拼）
#   --tenant <id>           Mimir 的 X-Scope-OrgID（同时用于"故意不带"对照）
#   --secret-dir <dir>      gen-ca.sh 产物目录（做 ③；缺则跳过）
#   --probe-image <image>   探测镜像（默认 docker.m.daocloud.io/library/busybox:1.36）
#   --kubeconfig <path>
#
# ── 用法 ─────────────────────────────────────────────────────────────────────
#   ./e6-batch2-assets.sh --tier all --secret-dir ./certs \
#       --receiver http://prometheus-central.otpmask.svc:9090 --tenant otpmask
#
# ── 退出码 ───────────────────────────────────────────────────────────────────
#   0 通过｜1 失败｜2 参数错误｜3 环境前置不满足
#
# ── 纪律 ─────────────────────────────────────────────────────────────────────
#   * 每个变更动作都有配对的清理（trap 兜底），**不留残留**；
#   * 任一子项未测 ⇒ 记 skip/blocked，**不因"其他两项通过"就宣称 PRE-B-9 闭环**。

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_PRE_OUT="${DRILL_OUT:-}"
# shellcheck source=../drills/_lib.sh
source "$HERE/../drills/_lib.sh"

DRILL_ID="PRE-B-9-batch2-assets"
DRILL_TITLE="PRE-B-9 批二资产真机取证（NP 三档 / 接收端 / Secret 卷）"
if [ -n "${_PRE_OUT:-}" ]; then DRILL_OUT="$_PRE_OUT"; else
  DRILL_OUT="$HERE/../../docs/verify/multicluster/evidence"
fi

NS="otpmask"; TIER=""; PROBE_SVC="gateway-core:8085"; PROBE_PATH="/healthz"
TENANT=""; SECRET_DIR=""; KCFG=""
PROBE_IMAGE="docker.m.daocloud.io/library/busybox:1.36"
RECEIVERS=()
NEW_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --ns)          NS="${2:-otpmask}"; shift 2; continue ;;
    --tier)        TIER="${2:-}"; shift 2; continue ;;
    --probe-svc)   PROBE_SVC="${2:-}"; shift 2; continue ;;
    --probe-path)  PROBE_PATH="${2:-/healthz}"; shift 2; continue ;;
    --receiver)    RECEIVERS+=("${2:-}"); shift 2; continue ;;
    --tenant)      TENANT="${2:-}"; shift 2; continue ;;
    --secret-dir)  SECRET_DIR="${2:-}"; shift 2; continue ;;
    --probe-image) PROBE_IMAGE="${2:-}"; shift 2; continue ;;
    --kubeconfig)  KCFG="${2:-}"; shift 2; continue ;;
    -h|--help) sed -n '2,44p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  esac
  NEW_ARGS+=("$1"); shift
done
_BEFORE_PARSE_OUT="$DRILL_OUT"
if [ ${#NEW_ARGS[@]} -gt 0 ]; then dr_parse_common "${NEW_ARGS[@]}"; else dr_parse_common; fi
# dry-run 绝不写 docs 证据目录：否则"预演"会被后任误当"证据"归档（DRILL_OUT 只有 --out 会改）
if [ "$DRY_RUN" = "1" ] && [ "$DRILL_OUT" = "$_BEFORE_PARSE_OUT" ]; then
  DRILL_OUT="$(dr_default_out_dir)/p24-evidence"
fi

KC="kubectl"
[ -n "$KCFG" ] && KC="kubectl --kubeconfig $KCFG"
export NS KC TENANT PROBE_IMAGE PROBE_SVC PROBE_PATH

TIER_DIR="$HERE/../../deploy/k8s-overlays/trust/networkpolicy-tiers"
PROBE_POD="p24-netpol-probe"
SECRET_NAME="p24-tls-probe"
SECRET_POD="p24-secret-probe"

dr_init
printf '== %s ==\n证据目录：%s\nns=%s tier=%s\n\n' "$DRILL_TITLE" "$DR_EVIDENCE_DIR" "$NS" "${TIER:-(跳过)}"

# 兜底清理：无论怎么退出，都不留下探测 Pod / 策略 / Secret
cleanup_probe() {
  $KC -n "$NS" delete pod "$PROBE_POD" --ignore-not-found --now >/dev/null 2>&1 || true
  $KC -n "$NS" delete pod "$SECRET_POD" --ignore-not-found --now >/dev/null 2>&1 || true
  $KC -n "$NS" delete secret "$SECRET_NAME" --ignore-not-found >/dev/null 2>&1 || true
}
trap 'cleanup_probe' EXIT

command -v kubectl >/dev/null 2>&1 || { dr_step env "kubectl" env_unmet "未安装/不在 PATH"; DR_ENV_UNMET=1; }
if [ "$DR_ENV_UNMET" = "0" ]; then
  dr_exec_ro e6-cluster "集群可达" "$KC cluster-info 2>&1 | head -2"
  if ! $KC get ns "$NS" >/dev/null 2>&1; then
    dr_step env "命名空间 $NS" env_unmet "不存在 → 三项均无法取证"
    DR_ENV_UNMET=1
  fi
fi
if [ "$DR_ENV_UNMET" = "1" ]; then dr_compute_exit_code 0; exit "$DR_FINAL_CODE"; fi

# ================= ① NetworkPolicy 三档 =================
run_tier() {
  local t="$1" f="$TIER_DIR/tier$1-$(case "$1" in 1) echo minimal;; 2) echo standard;; 3) echo permissive;; esac).yaml"
  if [ ! -f "$f" ]; then dr_skip "e6-np-$t" "档 $t" "文件不存在：$f"; return; fi

  if [ "$DRY_RUN" = "1" ]; then
    dr_dryrun "e6-np-$t" "档 $t apply/probe/rollback" \
      "将 apply $f → 探测 $PROBE_SVC$PROBE_PATH → delete -f $f"
    return
  fi

  if ! $KC apply -f "$f" >/dev/null 2>&1; then
    dr_fail "e6-np-$t" "档 $t apply" "apply 失败（占位符未替换？如 REPLACE_WITH_HIGRESS_NAMESPACE 属正常，须先填）"
    return
  fi
  dr_pass "e6-np-$t-apply" "档 $t apply" "已应用"

  # 探测：从同命名空间临时 Pod 发起（最小档应通；跨命名空间放行项按档位差异人工核对）
  local out rc
  out="$($KC -n "$NS" run "$PROBE_POD" --rm -i --restart=Never --image="$PROBE_IMAGE" \
        --labels="app=netpol-probe" --command -- \
        sh -c "wget -q -T 3 -O /dev/null 'http://$PROBE_SVC$PROBE_PATH' && echo REACHABLE || echo BLOCKED" 2>&1)"; rc=$?
  if printf '%s' "$out" | grep -q REACHABLE; then
    dr_pass "e6-np-$t-probe" "档 $t 连通探测" "$PROBE_SVC$PROBE_PATH 可达（同命名空间基线）"
  elif printf '%s' "$out" | grep -q BLOCKED; then
    dr_fail "e6-np-$t-probe" "档 $t 连通探测" "同命名空间基线被拦 → 该档放行项不完整（见 tier 文件注释）"
  else
    dr_fail "e6-np-$t-probe" "档 $t 连通探测" "探测未得出结果（rc=$rc）：$(printf '%s' "$out" | head -3)"
  fi

  # 必须回滚：三档加性，残留会污染后续判断
  if $KC delete -f "$f" >/dev/null 2>&1; then
    dr_pass "e6-np-$t-rollback" "档 $t 回滚" "已删除"
  else
    dr_fail "e6-np-$t-rollback" "档 $t 回滚" "删除失败 → **必须人工清理**，否则后续网络判断全部失真"
  fi
}

if [ -z "$TIER" ]; then
  dr_skip e6-np "NetworkPolicy 三档" "未给 --tier（默认不测：apply 策略会改变真实网络行为，须显式确认）"
elif [ "$TIER" = "all" ]; then
  # 注意：三档不可同时存在（加性 ⇒ 叠加=最宽），所以逐档"应用→探测→删除"
  for t in 1 2 3; do run_tier "$t"; done
else
  run_tier "$TIER"
fi

# ================= ② 四种接收端 =================
if [ ${#RECEIVERS[@]} -eq 0 ]; then
  dr_skip e6-recv "接收端连通" "未给 --receiver（可多次）；形态 A 才需要，形态 B 由 ① 之外的 central 栈自测"
else
  for url in "${RECEIVERS[@]}"; do
    # 缺租户头的那一组：Mimir 语义（X-Scope-OrgID 必填）——用自己的"不带头"请求验证拒绝
    if [ "$DRY_RUN" = "1" ]; then
      dr_dryrun "e6-recv" "接收端 $url" "将 POST 一个空 remote_write 请求并记录 HTTP 码"
      continue
    fi
    hdr=""
    [ -n "$TENANT" ] && hdr="-H 'X-Scope-OrgID: $TENANT'"
    dr_exec_ro "e6-recv" "接收端 $url（带租户头）" \
      "command -v curl >/dev/null || { echo no-curl; exit 0; }; curl -sS -o /dev/null -w '%{http_code}' -m 8 -X POST $hdr '${url%/}/api/v1/write' --data-binary ''"
    dr_exec_ro "e6-recv-nohdr" "接收端 $url（故意不带租户头，验证是否拒绝）" \
      "command -v curl >/dev/null || { echo no-curl; exit 0; }; curl -sS -o /dev/null -w '%{http_code}' -m 8 -X POST '${url%/}/api/v1/write' --data-binary ''"
  done
fi

# ================= ③ Secret 卷读权限（0440 vs 0400）=================
if [ -z "$SECRET_DIR" ]; then
  dr_skip e6-secret "Secret 卷读权限" "未给 --secret-dir（gen-ca.sh 产物目录）→ 此项是 PRE-A-11 的答案来源，缺它则 PRE-B-9 不闭环"
else
  for f in tls.crt tls.key ca.crt; do
    [ -f "$SECRET_DIR/$f" ] || { dr_blocked e6-secret "Secret 卷读权限" "缺少 $SECRET_DIR/$f"; break; }
  done
  for mode in 0440 0400; do
    if [ "$DRY_RUN" = "1" ]; then
      dr_dryrun "e6-secret-$mode" "defaultMode=$mode 下 65534 能否读私钥" \
        "将建 Secret → 挂载 defaultMode=$mode + fsGroup=65534 → cat 私钥"
      continue
    fi
    $KC -n "$NS" delete pod "$SECRET_POD" --ignore-not-found --now >/dev/null 2>&1 || true
    $KC -n "$NS" create secret generic "$SECRET_NAME" \
      --from-file=tls.crt="$SECRET_DIR/tls.crt" \
      --from-file=tls.key="$SECRET_DIR/tls.key" \
      --from-file=ca.crt="$SECRET_DIR/ca.crt" >/dev/null 2>&1 \
      || { dr_fail "e6-secret-$mode" "创建 Secret" "create 失败"; continue; }

    sed -e "s#__NS__#$NS#g" -e "s#__SECRET__#$SECRET_NAME#g" -e "s#__MODE__#$mode#g" \
        -e "s#__IMAGE__#$PROBE_IMAGE#g" > "$DR_EVIDENCE_DIR/probe-pod-$mode.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: p24-secret-probe
  namespace: __NS__
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    runAsGroup: 65534
    fsGroup: 65534
  containers:
  - name: probe
    image: __IMAGE__
    command: ["sh","-c","ls -l /etc/probe; cat /etc/probe/tls.key >/dev/null && echo READ_OK || echo READ_FAIL"]
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: tls
      mountPath: /etc/probe
      readOnly: true
  volumes:
  - name: tls
    secret:
      secretName: __SECRET__
      defaultMode: __MODE__
YAML

    if $KC apply -f "$DR_EVIDENCE_DIR/probe-pod-$mode.yaml" >/dev/null 2>&1; then
      $KC -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded pod/"$SECRET_POD" --timeout=60s >/dev/null 2>&1
      logs="$($KC -n "$NS" logs "$SECRET_POD" 2>&1)"
      if printf '%s' "$logs" | grep -q READ_OK; then
        dr_pass "e6-secret-$mode" "defaultMode=$mode 可读" "READ_OK（fsGroup=65534）"
      else
        dr_fail "e6-secret-$mode" "defaultMode=$mode 可读" "$(printf '%s' "$logs" | tr '\n' ' ' | head -c 300)"
      fi
      $KC -n "$NS" delete pod "$SECRET_POD" --ignore-not-found --now >/dev/null 2>&1 || true
    else
      dr_fail "e6-secret-$mode" "挂载探测 Pod" "apply 失败（见 probe-pod-$mode.yaml）"
    fi
    $KC -n "$NS" delete secret "$SECRET_NAME" --ignore-not-found >/dev/null 2>&1 || true
  done
fi

printf '\n完成。证据：%s\n' "$DR_EVIDENCE_DIR"
dr_write_evidence_md "\`PRE-B-9①\` 每档的探测结果（应通/应断各一组）与回滚确认；若档 3 里把 CIDR 收成 /32 后行为如何
\`PRE-B-9②\` 四种接收端各自的**成功码**（Prometheus 200 / Thanos 200 / Mimir 200 / VM **204**）与缺租户头的拒绝码
\`PRE-B-9③\` 最终采用的 defaultMode（0440 可读 / 0400 不可读）→ 这个值同时是 \`PRE-A-11\` 的答案，须回写部署资产
**三项分别独立判定：某项 skip 时整体结论写"部分闭环"，不得合并成一个 PASS**"
dr_compute_exit_code 0
exit "$DR_FINAL_CODE"
