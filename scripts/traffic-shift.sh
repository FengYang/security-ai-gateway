#!/usr/bin/env bash
# scripts/traffic-shift.sh — P2-4 T-5.2 切流/回切 SOP 执行器（预检→执行→观测→确认→记录）。
#
# 口径来源：docs/详细设计/P2/GA-AI网关能力补齐方案--P2--多集群管理.md
#   §6.4 调度配置模型（clusters[].{id,role,weight,health_source} + switch_policy）
#   D-5    不自研 GSLB/LB —— 执行点在**客户既有 DNS/GSLB/云 LB**
#   V-5    双集群主备切流演练：切换成功、业务影响窗口达 SOP 标称、回切可选
#
# ★ 本脚本**不实现调度器**：所有北向变更动作经外部钩子命令注入（NB_SET_WEIGHT_CMD 等），
#   钩子缺失 ⇒ 环境前置不满足（退出码 3），**不伪称成功**。
# ★ 默认人工确认（D-5）：switch_policy=manual 时须操作员显式确认才记录"已确认"；
#   semi-auto 仅在健康触发建议后仍需确认（脚本按建议执行，不跳过确认语义）。
#
# 五阶段：
#   1 预检 precheck：调度模型校验 → 健康源可达 → 依赖就绪 → 当前权重快照
#   2 执行 execute ：按权重把流量切向目标集群（经北向钩子）
#   3 观测 observe ：观测窗口内健康复检 + 业务指标钩子（可选）
#   4 确认 confirm ：人工确认（D-5）
#   5 记录 record ：产出 JSON 报告 + Markdown 留证骨架
#
# 失败回退：执行或观测失败 ⇒ 自动回退到回滚权重（回切路径），并在报告标注回退动作。
#
# 退出码：0 通过（skip 不计失败）｜1 失败/已回退｜2 参数错误｜3 环境前置不满足。
#
# 用法：
#   scripts/traffic-shift.sh --action switch --from cluster-a --to cluster-b \
#       [--config <调度配置.yaml>] [--from-weight 0] [--to-weight 100] \
#       [--gray-tier 5|25|50|100] [--critical-path] [--dns-ttl 60] \
#       [--dry-run] [--out <证据目录>]
#   scripts/traffic-shift.sh --action failback --from cluster-b --to cluster-a
#
# 注入环境变量（演练环境）：
#   NB_SET_WEIGHT_CMD  北向权重设置钩子（脚本注入 CLUSTER_ID / WEIGHT / PREV_WEIGHT）
#   NB_GET_WEIGHT_CMD  北向权重读取钩子（可选；脚本注入 CLUSTER_ID）
#   HEALTH_URL_<cluster> 或 HEALTH_URL_<CLUSTER 大写>  该集群健康源（§6.4 health_source）
#   PROM_URL           Prometheus 基址（观测用；缺省则观测指标步骤 skip）
#   OBSERVE_CMD        业务观测钩子（可选；脚本注入 CLUSTER_ID / WINDOW_SEC）
#   SWITCH_POLICY      manual（默认，D-5）| semi-auto
#   CONFIRM=1          跳过交互确认（已由操作员在带外确认；仅限有审计记录的场合）
#   IMPACT_WINDOW_SEC  标称业务影响窗口（秒，默认 30；观测窗口据此设定）
#   DNS_TTL_SEC        业务域名**当前实际** TTL（秒，默认 60）——**硬前置**：超过上限即拒绝切流
#   DNS_TTL_MAX_SEC    业务域名 TTL 上限（秒，默认 60；产品规格：业务域名 ≤60s）
#   CRITICAL_TTL_MAX_SEC 关键链路（登录/鉴权）TTL 上限（秒，默认 30）
#   CRITICAL_PATH      1=按关键链路口径校验 TTL（等价于 --critical-path）
#
# ★ TTL 硬前置（2026-10-26 新增）：切流前**必须**已把 DNS TTL 降到上限内，否则拒绝执行（退出码 3）。
#   原因：权重变更后，旧 TTL 未过期的客户端仍解析到旧集群 → 业务影响窗口不可控，
#   且"切流成功"的观测结论会被缓存流量污染。收敛时间 ≈ 旧 TTL（不是新 TTL）。
#   本脚本不替你改 TTL（北向 DNS 属客户执行点），只**校验**已填的实际值。
#
# ★ 灰度档位（2026-10-26 新增）：--gray-tier 按 5→25→50→100 逐档推进，脚本据档位推导
#   from/to 权重（不再要求手填两个数，避免"手填不一致"）。回切（failback）不支持灰度。

set -uo pipefail

_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=drills/_lib.sh
source "$_SELF_DIR/drills/_lib.sh"

ACTION="switch"
FROM_CLUSTER=""
TO_CLUSTER=""
CONFIG_FILE=""
FROM_WEIGHT="0"
TO_WEIGHT="100"
GRAY_TIER=""
CRITICAL_PATH="${CRITICAL_PATH:-0}"
CLUSTER_IDS=""

usage() {
  cat <<'EOF'
用法：
  traffic-shift.sh --action switch|failback --from <cluster> --to <cluster> [选项]

必选：
  --action switch|failback   switch=切向 --to；failback=回切（把权重切回 --from 侧）
  --from <cluster>            源集群（切流时被降权的集群）
  --to   <cluster>            目标集群（切流时承压的集群）

可选：
  --config <file>             §6.4 调度配置文件（clusters/switch_policy）
  --from-weight <n>           源集群权重（默认 0）
  --to-weight <n>             目标集群权重（默认 100）
  --gray-tier <5|25|50|100>   灰度档位：按档位推导 from/to 权重（5→25→50→100，逐档推进）
                              回切（failback）不支持灰度
  --critical-path             关键链路（登录/鉴权）口径：TTL 上限降为 30s
  --dns-ttl <n>               业务域名当前实际 TTL（秒，覆盖 DNS_TTL_SEC；硬前置校验用）
  --dry-run                   只读预演，不执行任何变更
  --out <dir>                 证据输出目录
  -h|--help                   本帮助

硬前置（不满足即退出码 3，不执行任何变更）：
  * NB_SET_WEIGHT_CMD 未注入（北向执行点未知）
  * DNS_TTL_SEC 超过上限（业务域名默认 ≤60s；--critical-path 时 ≤30s）
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --action) ACTION="${2:-}"; shift 2 ;;
    --from) FROM_CLUSTER="${2:-}"; shift 2 ;;
    --to) TO_CLUSTER="${2:-}"; shift 2 ;;
    --config) CONFIG_FILE="${2:-}"; shift 2 ;;
    --from-weight) FROM_WEIGHT="${2:-}"; shift 2 ;;
    --to-weight) TO_WEIGHT="${2:-}"; shift 2 ;;
    --gray-tier) GRAY_TIER="${2:-}"; shift 2 ;;
    --gray-tier=*) GRAY_TIER="${1#*=}"; shift ;;
    --critical-path) CRITICAL_PATH=1; shift ;;
    --dns-ttl) DNS_TTL_SEC="${2:-}"; shift 2 ;;
    --dns-ttl=*) DNS_TTL_SEC="${1#*=}"; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --out) DRILL_OUT="${2:-}"; shift 2 ;;
    --out=*) DRILL_OUT="${1#*=}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数：$1" >&2; usage; exit "$DR_EXIT_ARGS" ;;
  esac
done

case "$ACTION" in
  switch | failback) ;;
  *) echo "--action 必须是 switch 或 failback（收到 '$ACTION'）" >&2; usage; exit "$DR_EXIT_ARGS" ;;
esac
[ -n "$FROM_CLUSTER" ] && [ -n "$TO_CLUSTER" ] || { echo "--from/--to 必填" >&2; exit "$DR_EXIT_ARGS"; }
[ "$FROM_CLUSTER" != "$TO_CLUSTER" ] || { echo "--from 与 --to 不能相同" >&2; exit "$DR_EXIT_ARGS"; }
case "$FROM_WEIGHT$TO_WEIGHT" in
  ''|*[!0-9]*) echo "--from-weight/--to-weight 必须是非负整数" >&2; exit "$DR_EXIT_ARGS" ;;
esac
[ "$TO_WEIGHT" -le 100 ] && [ "$FROM_WEIGHT" -le 100 ] || {
  echo "权重必须在 0..100（§6.4 归一化口径）" >&2; exit "$DR_EXIT_ARGS"; }

# 灰度档位：由档位推导权重（避免手填 from/to 不一致）；回切不走灰度
GRAY_TIERS="5 25 50 100"
if [ -n "$GRAY_TIER" ]; then
  case " $GRAY_TIERS " in
    *" $GRAY_TIER "*) ;;
    *) echo "--gray-tier 必须是 5/25/50/100 之一（收到 '$GRAY_TIER'）" >&2; exit "$DR_EXIT_ARGS" ;;
  esac
  if [ "$ACTION" = "failback" ]; then
    echo "--gray-tier 仅用于切流（switch）；回切（failback）是直接恢复，不做灰度" >&2
    exit "$DR_EXIT_ARGS"
  fi
  TO_WEIGHT="$GRAY_TIER"
  FROM_WEIGHT=$((100 - GRAY_TIER))
fi

# 回切语义：failback 时目标权重 = 原源集群权重，源权重 = 原目标权重
if [ "$ACTION" = "failback" ]; then
  tmp="$FROM_WEIGHT"; FROM_WEIGHT="$TO_WEIGHT"; TO_WEIGHT="$tmp"
fi

DRILL_ID="t5.2-traffic-shift"
DRILL_TITLE="切流/回切（T-5.2，action=$ACTION，$FROM_CLUSTER → $TO_CLUSTER${GRAY_TIER:+，灰度 ${GRAY_TIER}%}）"
IMPACT_WINDOW_SEC="${IMPACT_WINDOW_SEC:-30}"
DNS_TTL_SEC="${DNS_TTL_SEC:-60}"
DNS_TTL_MAX_SEC="${DNS_TTL_MAX_SEC:-60}"
CRITICAL_TTL_MAX_SEC="${CRITICAL_TTL_MAX_SEC:-30}"
SWITCH_POLICY="${SWITCH_POLICY:-manual}"

dr_init

# ---------- 调度模型解析（§6.4）----------
# 输出：CLUSTER|id|role|weight|health_source  与  POLICY|manual|semi-auto
parse_schedule_file() {
  awk '
    function flush() {
      if (id != "") print "CLUSTER|" id "|" role "|" weight "|" hs
      id=""; role=""; weight=""; hs=""
    }
    /^[[:space:]]*-[[:space:]]*id:[[:space:]]*/ {
      flush(); line=$0; sub(/^[^:]*:[[:space:]]*/,"",line); gsub(/"/,"",line); gsub(/[[:space:]]/,"",line); id=line; next
    }
    /^[[:space:]]*role:[[:space:]]*/ {
      line=$0; sub(/^[^:]*:[[:space:]]*/,"",line); gsub(/"/,"",line); gsub(/[[:space:]]/,"",line); role=line; next
    }
    /^[[:space:]]*weight:[[:space:]]*/ {
      line=$0; sub(/^[^:]*:[[:space:]]*/,"",line); gsub(/"/,"",line); gsub(/[[:space:]]/,"",line); weight=line; next
    }
    /^[[:space:]]*health_source:[[:space:]]*/ {
      line=$0; sub(/^[^:]*:[[:space:]]*/,"",line); gsub(/"/,"",line); hs=line; next
    }
    /^switch_policy:[[:space:]]*/ {
      line=$0; sub(/^[^:]*:[[:space:]]*/,"",line); gsub(/"/,"",line); gsub(/[[:space:]]/,"",line); print "POLICY|" line; next
    }
    END { flush() }
  ' "$1"
}

# ---------- 阶段 1：预检 ----------
dr_step "1-precheck" "预检（模型/健康/依赖）" pass "开始"

# 1.1 调度配置模型校验
MODEL_ROLES="primary standby weighted"
if [ -n "$CONFIG_FILE" ]; then
  if [ ! -f "$CONFIG_FILE" ]; then
    dr_fail "1.1-model" "调度配置模型校验" "配置文件不存在：$CONFIG_FILE"
  else
    MODEL_PARSED="$(parse_schedule_file "$CONFIG_FILE")"
    CLUSTER_IDS="$(printf '%s\n' "$MODEL_PARSED" | awk -F'|' '$1=="CLUSTER"{print $2}')"
    FILE_POLICY="$(printf '%s\n' "$MODEL_PARSED" | awk -F'|' '$1=="POLICY"{print $2}')"
    model_err=""
    while IFS='|' read -r _tag cid role weight _hs; do
      [ "$_tag" = "CLUSTER" ] || continue
      case " $MODEL_ROLES " in
        *" $role "*) ;;
        *) model_err="$model_err 非法 role='$role'（cluster=$cid；允许 primary|standby|weighted）" ;;
      esac
      case "$weight" in
        ''|*[!0-9]*) model_err="$model_err 非法 weight='$weight'（cluster=$cid）" ;;
        *) [ "$weight" -le 100 ] || model_err="$model_err weight>100（cluster=$cid）" ;;
      esac
    done <<< "$MODEL_PARSED"
    if ! printf '%s\n' "$CLUSTER_IDS" | grep -qx "$TO_CLUSTER"; then
      model_err="$model_err 目标集群 '$TO_CLUSTER' 不在调度模型中"
    fi
    if ! printf '%s\n' "$CLUSTER_IDS" | grep -qx "$FROM_CLUSTER"; then
      model_err="$model_err 源集群 '$FROM_CLUSTER' 不在调度模型中"
    fi
    case "$FILE_POLICY" in
      manual | semi-auto) ;;
      *) model_err="$model_err 非法 switch_policy='$FILE_POLICY'（允许 manual|semi-auto）" ;;
    esac
    if [ -n "$model_err" ]; then
      dr_fail "1.1-model" "调度配置模型校验" "$model_err"
    else
      dr_pass "1.1-model" "调度配置模型校验" "clusters=[$(printf '%s' "$CLUSTER_IDS" | tr '\n' ' ')] switch_policy=${FILE_POLICY:-manual}（§6.4）"
      [ -n "$FILE_POLICY" ] && SWITCH_POLICY="$FILE_POLICY"
    fi
  fi
else
  dr_skip "1.1-model" "调度配置模型校验" "未提供 --config（仅按 --from/--to 与权重执行；模型校验留待配置接入后）"
fi

# 1.2 依赖就绪：北向变更钩子（缺 ⇒ 环境不满足，退出 3）
if ! dr_require_env "北向权重变更钩子" NB_SET_WEIGHT_CMD; then
  dr_write_report; dr_write_evidence_md "- 北向变更钩子（NB_SET_WEIGHT_CMD）：TODO(人工) —— 客户 DNS/GSLB/云 LB 的实际变更入口
- 客户侧审批单号：TODO(人工)"; exit "$DR_EXIT_ENV"
fi
dr_pass "1.2-deps" "依赖就绪" "NB_SET_WEIGHT_CMD 已注入（北向执行点＝客户既有 DNS/GSLB/云 LB，D-5）"

# 1.3 健康源可达（§6.4 health_source）
health_ok=1
for cid in "$FROM_CLUSTER" "$TO_CLUSTER"; do
  url="$(dr_health_url_of "$cid")" || url=""
  if [ -z "$url" ]; then
    dr_skip "1.3-health-$cid" "健康源探测 $cid" "未配置 HEALTH_URL（$cid）"
    continue
  fi
  code="$(dr_http_code "$url")"
  case "$code" in
    2??) dr_pass "1.3-health-$cid" "健康源探测 $cid" "HTTP $code $url" ;;
    *) dr_fail "1.3-health-$cid" "健康源探测 $cid" "HTTP $code $url（目标集群不健康时禁止切流）"; health_ok=0 ;;
  esac
done
if [ "$health_ok" -ne 1 ]; then
  dr_incident "预检发现健康异常，未执行切流（fail-closed）"
  dr_write_report; dr_write_evidence_md "- 健康源与健康判定口径：TODO(人工)"; exit "$DR_EXIT_FAIL"
fi

# 1.4 当前权重快照（只读）
CUR_FROM=""; CUR_TO=""
if [ -n "${NB_GET_WEIGHT_CMD:-}" ]; then
  export CLUSTER_ID="$FROM_CLUSTER"
  cur="$(bash -c "$NB_GET_WEIGHT_CMD" 2>&1)"; rc=$?
  [ $rc -eq 0 ] && CUR_FROM="$cur" || dr_skip "1.4-curw-$FROM_CLUSTER" "当前权重快照 $FROM_CLUSTER" "读取失败 exit $rc：$cur"
  export CLUSTER_ID="$TO_CLUSTER"
  cur="$(bash -c "$NB_GET_WEIGHT_CMD" 2>&1)"; rc=$?
  [ $rc -eq 0 ] && CUR_TO="$cur" || dr_skip "1.4-curw-$TO_CLUSTER" "当前权重快照 $TO_CLUSTER" "读取失败 exit $rc：$cur"
  dr_pass "1.4-curw" "当前权重快照" "from($FROM_CLUSTER)=$CUR_FROM to($TO_CLUSTER)=$CUR_TO"
else
  dr_skip "1.4-curw" "当前权重快照" "未注入 NB_GET_WEIGHT_CMD（只读钩子可选）"
fi

# 1.5 DNS TTL 硬前置（切流前必须已降 TTL；未降即拒，退出 3）
#   · 权重变更后旧 TTL 未过期的客户端仍解析到旧集群 → 影响窗口不可控
#   · 收敛时间 ≈ **旧** TTL（不是新 TTL），故必须在切流前就降好并等其过期
case "$DNS_TTL_SEC" in
  '' | *[!0-9]*) echo "DNS_TTL_SEC 必须是正整数秒（收到 '$DNS_TTL_SEC'）" >&2; exit "$DR_EXIT_ARGS" ;;
esac
TTL_MAX="$DNS_TTL_MAX_SEC"
TTL_SCOPE="业务域名"
if [ "$CRITICAL_PATH" = "1" ]; then
  TTL_MAX="$CRITICAL_TTL_MAX_SEC"
  TTL_SCOPE="关键链路（登录/鉴权）"
fi
case "$TTL_MAX" in
  '' | *[!0-9]*) echo "TTL 上限必须是正整数秒（DNS_TTL_MAX_SEC=$DNS_TTL_MAX_SEC / CRITICAL_TTL_MAX_SEC=$CRITICAL_TTL_MAX_SEC）" >&2; exit "$DR_EXIT_ARGS" ;;
esac
if [ "$DNS_TTL_SEC" -gt "$TTL_MAX" ]; then
  if [ "$DRY_RUN" = "1" ]; then
    dr_skip "1.5-ttl" "DNS TTL 前置（${TTL_SCOPE} ≤${TTL_MAX}s）" \
      "dry-run：当前 DNS_TTL_SEC=${DNS_TTL_SEC}s 超上限 ${TTL_MAX}s；**实跑将拒绝（exit 3）**——切流前须先降 TTL 并等旧 TTL 过期"
  else
    dr_fail "1.5-ttl" "DNS TTL 前置（${TTL_SCOPE} ≤${TTL_MAX}s）" \
      "当前 DNS_TTL_SEC=${DNS_TTL_SEC}s > 上限 ${TTL_MAX}s —— 拒绝切流。请先把 ${TTL_SCOPE} TTL 降到 ≤${TTL_MAX}s，并等待一个旧 TTL 周期使其收敛，再重跑本脚本"
    dr_write_report
    dr_write_evidence_md "- DNS TTL 现状与降 TTL 时间：TODO(人工)
- 旧 TTL 过期确认时间：TODO(人工)"
    exit "$DR_EXIT_ENV"
  fi
else
  dr_pass "1.5-ttl" "DNS TTL 前置（${TTL_SCOPE} ≤${TTL_MAX}s）" \
    "DNS_TTL_SEC=${DNS_TTL_SEC}s ≤ ${TTL_MAX}s（已降 TTL；切流收敛时间≈旧 TTL）"
fi

# 1.6 灰度档位（仅 --gray-tier 时；档序 5→25→50→100，逐档观测后再推进）
if [ -n "$GRAY_TIER" ]; then
  case "$GRAY_TIER" in
    5) _tier_no=1 ;;
    25) _tier_no=2 ;;
    50) _tier_no=3 ;;
    100) _tier_no=4 ;;
    *) _tier_no="?" ;;
  esac
  dr_pass "1.6-gray" "灰度档位" \
    "第 ${_tier_no}/4 档：${GRAY_TIER}%（from=$FROM_CLUSTER weight=$FROM_WEIGHT → to=$TO_CLUSTER weight=$TO_WEIGHT）；每档观测通过后再推进下一档"
else
  dr_skip "1.6-gray" "灰度档位" "未指定 --gray-tier（按 --from-weight/--to-weight 直接切；建议正式切流走灰度 5→25→50→100）"
fi

dr_step "1-precheck" "预检（模型/健康/依赖）" pass "预检完成"

# ---------- 阶段 2：执行 ----------
export PREV_WEIGHT="$CUR_TO"
export WEIGHT="$TO_WEIGHT"
export CLUSTER_ID="$TO_CLUSTER"
dr_exec "2-exec-target" "切向 $TO_CLUSTER（weight=$TO_WEIGHT）" "$NB_SET_WEIGHT_CMD"
exec_rc=$?
export PREV_WEIGHT="$CUR_FROM"
export WEIGHT="$FROM_WEIGHT"
export CLUSTER_ID="$FROM_CLUSTER"
dr_exec "2-exec-source" "降权 $FROM_CLUSTER（weight=$FROM_WEIGHT）" "$NB_SET_WEIGHT_CMD"
src_rc=$?

# ---------- 失败回退（failback 路径）----------
if [ "$exec_rc" -ne 0 ] || [ "$src_rc" -ne 0 ]; then
  dr_incident "执行阶段失败，触发自动回退（恢复 $FROM_CLUSTER 原权重 ${CUR_FROM:-unknown}）"
  export CLUSTER_ID="$TO_CLUSTER"; export WEIGHT="${CUR_TO:-$FROM_WEIGHT}"; export PREV_WEIGHT="$TO_WEIGHT"
  dr_exec "2-rollback-target" "回退 $TO_CLUSTER 权重" "$NB_SET_WEIGHT_CMD"
  export CLUSTER_ID="$FROM_CLUSTER"; export WEIGHT="${CUR_FROM:-$TO_WEIGHT}"; export PREV_WEIGHT="$FROM_WEIGHT"
  dr_exec "2-rollback-source" "回退 $FROM_CLUSTER 权重" "$NB_SET_WEIGHT_CMD"
  dr_write_report
  dr_write_evidence_md "- 回退动作是否成功：TODO(人工)复核北向实际权重
- 回退期间业务影响：TODO(人工)"
  exit "$DR_EXIT_FAIL"
fi

# ---------- 阶段 3：观测 ----------
dr_step "3-observe" "观测（窗口 ${IMPACT_WINDOW_SEC}s）" pass "开始"
# 3.1 目标集群健康复检
url="$(dr_health_url_of "$TO_CLUSTER")" || url=""
if [ -n "$url" ]; then
  code="$(dr_http_code "$url")"
  if dr_dryrun_dependent "3.1-health" "切后健康复检 $TO_CLUSTER" "须在切流生效后成立；dry-run 未切流故不断言"; then
    :
  else
    case "$code" in
      2??) dr_pass "3.1-health" "切后健康复检 $TO_CLUSTER" "HTTP $code $url" ;;
      *) dr_fail "3.1-health" "切后健康复检 $TO_CLUSTER" "HTTP $code $url（切后不健康 ⇒ 回退）" ;;
    esac
  fi
else
  dr_skip "3.1-health" "切后健康复检 $TO_CLUSTER" "未配置 HEALTH_URL"
fi
# 3.2 业务观测钩子
if [ -n "${OBSERVE_CMD:-}" ]; then
  export CLUSTER_ID="$TO_CLUSTER"; export WINDOW_SEC="$IMPACT_WINDOW_SEC"
  dr_exec_ro "3.2-observe" "业务观测（$TO_CLUSTER，窗口 ${IMPACT_WINDOW_SEC}s）" "$OBSERVE_CMD"
elif [ -n "${PROM_URL:-}" ]; then
  dr_skip "3.2-observe" "业务观测" "PROM_URL 已配置但未注入 OBSERVE_CMD；指标查询口径须按现场指标名定制（见 SOP §4.3）"
else
  dr_skip "3.2-observe" "业务观测" "未注入 OBSERVE_CMD / PROM_URL（观测项 skip，不计失败）"
fi
# 3.3 影响窗口登记
dr_pass "3.3-window" "业务影响窗口" "标称 ${IMPACT_WINDOW_SEC}s（DNS TTL=${DNS_TTL_SEC}s${GRAY_TIER:+，灰度 ${GRAY_TIER}%}；权重生效与 TTL 收敛取大者）"

# 若观测失败 ⇒ 回退
if grep -q '"result":"fail"' "$DR_STEPS_FILE" 2>/dev/null && [ "$DR_FAILED" -eq 1 ]; then
  dr_incident "观测阶段存在失败步骤，触发自动回退（恢复 $FROM_CLUSTER 原权重 ${CUR_FROM:-unknown}）"
  export CLUSTER_ID="$TO_CLUSTER"; export WEIGHT="${CUR_TO:-$FROM_WEIGHT}"; export PREV_WEIGHT="$TO_WEIGHT"
  dr_exec "3-rollback-target" "回退 $TO_CLUSTER 权重" "$NB_SET_WEIGHT_CMD"
  export CLUSTER_ID="$FROM_CLUSTER"; export WEIGHT="${CUR_FROM:-$TO_WEIGHT}"; export PREV_WEIGHT="$FROM_WEIGHT"
  dr_exec "3-rollback-source" "回退 $FROM_CLUSTER 权重" "$NB_SET_WEIGHT_CMD"
  dr_write_report
  dr_write_evidence_md "- 回退后业务恢复时间：TODO(人工)
- 影响窗口实测（切流起→恢复）：TODO(人工)"
  exit "$DR_EXIT_FAIL"
fi
dr_step "3-observe" "观测" pass "观测完成"

# ---------- 阶段 4：确认（D-5 默认人工确认）----------
dr_step "4-confirm" "确认（switch_policy=$SWITCH_POLICY）" pass "开始"
if [ "$SWITCH_POLICY" = "semi-auto" ]; then
  dr_step "4-confirm" "确认（semi-auto：健康触发建议）" pass "健康触发已给出切流建议，仍按 D-5 保留人工确认语义"
fi
if ! dr_confirm_gate "确认 $FROM_CLUSTER → $TO_CLUSTER 切流已生效且业务正常？（默认人工确认，D-5）"; then
  dr_write_report
  dr_write_evidence_md "- 人工确认记录（操作员/时间/工单号）：TODO(人工)"
  exit "$DR_EXIT_FAIL"
fi

# ---------- 阶段 5：记录 ----------
dr_write_report
dr_write_evidence_md "- 人工确认记录（操作员/时间/工单号）：TODO(人工)
- 北向实际权重（切后）：TODO(人工)从客户 DNS/GSLB/云 LB 控制台核对
- 业务影响窗口实测：TODO(人工)
- DNS TTL：${DNS_TTL_SEC}s（上限 ${TTL_MAX}s，口径=${TTL_SCOPE}）；降 TTL 时间：TODO(人工)
- 灰度档位：${GRAY_TIER:-未使用灰度}
- 回切预案是否演练：TODO(人工)（回切＝本脚本 --action failback）"
printf '报告：%s\n' "$DR_EVIDENCE_DIR/report.json"
# 退出码由主流程一处决定（★ EXIT trap 只做收尾写报告，不改变已决定的退出状态）。
dr_compute_exit_code $?
exit "$DR_FINAL_CODE"
