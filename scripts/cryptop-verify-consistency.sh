#!/usr/bin/env bash
# scripts/cryptop-verify-consistency.sh —— P0-4 §12.6 全域一致性校验（B5-c；§7.5）。
#
# 切后校验：
#   1. sidecar GET /v1/capabilities：profile 须 == 目标（$1，给出时）；
#   2. mask_prg × profile 合法矩阵（R-14/R-21：intl 仅 hmac-sha256；sm-* 仅 sm4/bridge）；
#   3. CRYPTO_CONSISTENCY_TARGETS（空格分隔的 Go 服务 base URL）逐个探活
#      （GET $base$PROBE_PATH，默认 /healthz，须 2xx）。
#
# 退出码：0 通过；4 sidecar 不可达/响应缺字段；5 profile/mask_prg 不一致或非法；
#         6 被检服务探活失败。
#
# 环境：CRYPTOPSVC_URL（默认 http://127.0.0.1:8082）/ PROBE_PATH（默认 /healthz）/
# CRYPTO_CONSISTENCY_TARGETS（缺省仅校验 sidecar）。
set -euo pipefail

WANT="${1:-}"
CRYPTOPSVC_URL="${CRYPTOPSVC_URL:-http://127.0.0.1:8082}"
PROBE_PATH="${PROBE_PATH:-/healthz}"

resp=$(curl -sS --max-time 3 "$CRYPTOPSVC_URL/v1/capabilities") || {
  echo "sidecar capabilities 不可达: $CRYPTOPSVC_URL" >&2
  exit 4
}

# 字段提取（capabilities 契约保证 JSON 单行字段；sed 提取首处匹配）。
got_profile=$(echo "$resp" | sed -n 's/.*"profile":"\([^"]*\)".*/\1/p')
got_prg=$(echo "$resp" | sed -n 's/.*"mask_prg":"\([^"]*\)".*/\1/p')

if [ -z "$got_profile" ]; then
  echo "capabilities 响应缺 profile: $resp" >&2
  exit 4
fi

if [ -n "$WANT" ] && [ "$got_profile" != "$WANT" ]; then
  echo "profile 不一致：期望=$WANT sidecar=$got_profile（半切换，§7.5）" >&2
  exit 5
fi

# mask_prg × profile 合法矩阵（R-14/R-21）。
case "$got_profile" in
  intl)
    if [ "$got_prg" != "hmac-sha256" ]; then
      echo "intl profile 非法 mask_prg=$got_prg（R-14）" >&2
      exit 5
    fi
    ;;
  sm-software | sm-module)
    case "$got_prg" in
      sm4 | bridge) ;;
      *)
        echo "sm profile 非法 mask_prg=$got_prg（R-14/R-21）" >&2
        exit 5
        ;;
    esac
    ;;
  *)
    echo "sidecar 上报未知 profile=$got_profile（R-1）" >&2
    exit 5
    ;;
esac

# 各 Go 服务探活（无 TARGETS 时跳过：sidecar 是唯一强制校验项）。
for base in ${CRYPTO_CONSISTENCY_TARGETS:-}; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 "$base$PROBE_PATH") || {
    echo "服务探活失败: $base$PROBE_PATH" >&2
    exit 6
  }
  case "$code" in
    2??) ;;
    *)
      echo "服务非健康: $base HTTP $code" >&2
      exit 6
      ;;
  esac
done

echo "consistency OK: profile=$got_profile mask_prg=$got_prg"
