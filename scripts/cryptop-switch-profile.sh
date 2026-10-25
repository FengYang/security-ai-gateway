#!/usr/bin/env bash
# scripts/cryptop-switch-profile.sh —— P0-4 §12.6 profile 切换/回滚脚本（B5-c）。
#
# 职责（§12.6）：调 POST /v1/adminext/cryptop/profile（§4.3.10），按响应判分支：
#   restart_required（跨 provider + MODE=hot）→ exit 3；
#   其它拒绝（stale_from / inconsistent / bad_request / ok 非 true）→ exit 2；
#   成功 → 调同目录 cryptop-verify-consistency.sh 做全域一致性校验（§7.5）。
#
# 环境/入参：FROM（必填）/ TO（必填）/ MODE（默认 restart）/ PRG（缺省不动 mask_prg）/
# ADMIN（默认 http://127.0.0.1:8081）/ ADMIN_TOKEN（必填：端点强制 admin 角色）/
# CRYPTOPSVC_URL（verify 步骤用，默认 http://127.0.0.1:8082）。
set -euo pipefail

: "${FROM:?用法: FROM=<profile> TO=<profile> [MODE=restart|hot] [PRG=hmac-sha256|sm4|bridge]}"
: "${TO:?缺少 TO}"
MODE="${MODE:-restart}"
PRG="${PRG:-}"
ADMIN="${ADMIN:-http://127.0.0.1:8081}"
: "${ADMIN_TOKEN:?ADMIN_TOKEN 未设置（§4.3.10 端点强制 admin 鉴权）}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# -s（不 -f）：非 2xx 不提前退出，交给下方按 body 判分支（restart_required 亦为错误响应，须先判）。
body="{\"from\":\"$FROM\",\"to\":\"$TO\",\"mode\":\"$MODE\",\"confirm\":true}"
if [ -n "$PRG" ]; then
  body="{\"from\":\"$FROM\",\"to\":\"$TO\",\"mode\":\"$MODE\",\"mask_prg\":\"$PRG\",\"confirm\":true}"
fi

resp=$(curl -sS --max-time 5 -X POST "$ADMIN/v1/adminext/cryptop/profile" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d "$body") || {
  echo "profile switch request failed: $resp" >&2
  exit 1
}

# ① 先判 restart_required（跨 provider 形态 + mode=hot，退出码 3；v1.5 R6-P2-1）——
#    否则会被下方 ok 分支截断。if 条件中的 grep 失败不受 set -e 影响。
if echo "$resp" | grep -q '"restart_required"'; then
  echo "rolling restart required (cross-provider): $resp" >&2
  exit 3
fi
# ② 其它失败（stale_from / inconsistent / bad_request / ok 非 true）→ exit 2。
if ! echo "$resp" | grep -q '"ok":true'; then
  echo "rejected: $resp" >&2
  exit 2
fi
# ③ 一致性校验（§7.5）：全域 crypto_profile/mask_prg 一致。
CRYPTOPSVC_URL="${CRYPTOPSVC_URL:-http://127.0.0.1:8082}" \
  "$SCRIPT_DIR/cryptop-verify-consistency.sh" "$TO"
echo "profile switch applied: $TO (mode=$MODE)"
