#!/usr/bin/env bash
# deploy/tlcp/verify.sh —— P0-4 §12.4 TLCP 国密前置验证（B6#10；T-12.4-1..3）。
#
#   T-12.4-1 TLCP 握手：s_client -ntls 协商到 SM2/SM4 密码套件与 TLCP 协议
#   T-12.4-2 双证书链：签名证书 + 加密证书均验证到 SM2 根，且公钥为 SM2、彼此独立
#   T-12.4-3 双层叠加：外层 TLCP 之外，内层应用信封 suite 字节 = 0x02（SM4-GCM）；
#                      未提供 ENVELOPE_FILE 时 SKIP
#
# 退出码：0 全部通过（SKIP 不算失败）；1 断言失败；7 Tongsuo 不可用（全部 SKIP）；
#         8 参数错误。
#
# 变量（均可由环境覆盖）：GATEWAY_HOST（默认 127.0.0.1）/ GATEWAY_PORT（默认 443）/
# TONGSUO_BIN（默认 tongsuo）/ CA_FILE / SIGN_CERT / ENC_CERT（默认 deploy/tlcp/certs/*）/
# CIPHER_SUITE（默认 ECC-SM2-WITH-SM4-GCM-SM3）/ ENVELOPE_FILE（内层信封样本，可选）。
set -euo pipefail

GATEWAY_HOST="${GATEWAY_HOST:-127.0.0.1}"
GATEWAY_PORT="${GATEWAY_PORT:-443}"
TONGSUO_BIN="${TONGSUO_BIN:-tongsuo}"
CA_FILE="${CA_FILE:-deploy/tlcp/certs/ca.crt}"
SIGN_CERT="${SIGN_CERT:-deploy/tlcp/certs/sign.crt}"
ENC_CERT="${ENC_CERT:-deploy/tlcp/certs/enc.crt}"
CIPHER_SUITE="${CIPHER_SUITE:-ECC-SM2-WITH-SM4-GCM-SM3}"
ENVELOPE_FILE="${ENVELOPE_FILE:-}"

if [ -z "$GATEWAY_HOST" ] || [ -z "$GATEWAY_PORT" ]; then
  echo "GATEWAY_HOST/GATEWAY_PORT 不得为空" >&2
  exit 8
fi

# 每项结果：pass / fail / skip + 详情
r1="skip"; d1=""
r2="skip"; d2=""
r3="skip"; d3=""
final_exit=0

json_escape() { sed 's/\\/\\\\/g; s/"/\\"/g'; }

emit_evidence() {
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "-")
  printf '{\n'
  printf '  "timestamp": "%s",\n' "$ts"
  printf '  "gateway": "%s:%s",\n' "$GATEWAY_HOST" "$GATEWAY_PORT"
  printf '  "cipher_suite": "%s",\n' "$(printf '%s' "$CIPHER_SUITE" | json_escape)"
  printf '  "T-12.4-1": {"name":"tlcp_handshake","result":"%s","detail":"%s"},\n' \
    "$r1" "$(printf '%s' "$d1" | json_escape)"
  printf '  "T-12.4-2": {"name":"dual_cert_chain","result":"%s","detail":"%s"},\n' \
    "$r2" "$(printf '%s' "$d2" | json_escape)"
  printf '  "T-12.4-3": {"name":"double_layer","result":"%s","detail":"%s"}\n' \
    "$r3" "$(printf '%s' "$d3" | json_escape)"
  printf '}\n'
}

# Tongsuo 不可用：三项全 SKIP，证据 JSON 照出（exit 7）。
if ! command -v "$TONGSUO_BIN" >/dev/null 2>&1; then
  d1="tongsuo 二进制不可用（$TONGSUO_BIN）"
  d2="$d1"
  d3="$d1；另需 ENVELOPE_FILE"
  emit_evidence
  exit 7
fi

# ---- T-12.4-1：TLCP 握手 ----
client_out=$("$TONGSUO_BIN" s_client -connect "$GATEWAY_HOST:$GATEWAY_PORT" \
  -ntls -cipher "$CIPHER_SUITE" -CAfile "$CA_FILE" </dev/null 2>&1) || true
if printf '%s' "$client_out" | grep -q 'TLCP' && \
   printf '%s' "$client_out" | grep -qE 'Cipher\s*:\s*ECC-SM2-WITH-SM4'; then
  r1="pass"
  negotiated=$(printf '%s' "$client_out" | sed -n 's/.*Cipher[[:space:]]*:[[:space:]]*\(ECC-SM2-WITH-SM[0-9A-Z-]*\).*/\1/p' | head -1)
  d1="protocol=TLCP cipher=${negotiated:-$CIPHER_SUITE}"
else
  r1="fail"
  d1="未协商到 TLCP + ECC-SM2-WITH-SM4（检查网关 NTLS/套件/证书）"
  final_exit=1
fi

# ---- T-12.4-2：双证书链 ----
for f in "$CA_FILE" "$SIGN_CERT" "$ENC_CERT"; do
  if [ ! -f "$f" ]; then
    r2="fail"; d2="证书文件不存在: $f"; final_exit=1
    break
  fi
done
if [ "$r2" != "fail" ]; then
  if verify_out=$("$TONGSUO_BIN" verify -CAfile "$CA_FILE" "$SIGN_CERT" "$ENC_CERT" 2>&1); then
    # 公钥算法须为 SM2（OID 1.2.156.10197.1.301），且两证书公钥不同
    sign_text=$("$TONGSUO_BIN" x509 -in "$SIGN_CERT" -text -noout 2>/dev/null) || true
    enc_text=$("$TONGSUO_BIN" x509 -in "$ENC_CERT" -text -noout 2>/dev/null) || true
    sign_spki=$("$TONGSUO_BIN" x509 -in "$SIGN_CERT" -pubkey -noout 2>/dev/null) || true
    enc_spki=$("$TONGSUO_BIN" x509 -in "$ENC_CERT" -pubkey -noout 2>/dev/null) || true
    if printf '%s%s' "$sign_text" "$enc_text" | grep -q '1.2.156.10197.1.301' && \
       [ -n "$sign_spki" ] && [ "$sign_spki" != "$enc_spki" ]; then
      r2="pass"; d2="sign/enc 均链至 SM2 根；公钥 SM2 且彼此独立"
    else
      r2="fail"; d2="证书非 SM2 或签名/加密公钥相同"; final_exit=1
    fi
  else
    r2="fail"; d2="双证书链验证失败: $(printf '%s' "$verify_out" | tr '\n' ' ')"; final_exit=1
  fi
fi

# ---- T-12.4-3：双层叠加（内层信封 suite=0x02）----
if [ -n "$ENVELOPE_FILE" ]; then
  if [ ! -f "$ENVELOPE_FILE" ]; then
    r3="fail"; d3="ENVELOPE_FILE 不存在: $ENVELOPE_FILE"; final_exit=1
  else
    first=$(xxd -p -l 1 "$ENVELOPE_FILE" 2>/dev/null | tr -d '[:space:]') || true
    if [ "$first" = "02" ]; then
      r3="pass"; d3="内层信封 suite=0x02（SM4-GCM），与外层 TLCP 独立"
    else
      r3="fail"; d3="内层信封首字节=0x${first:-??}（期望 02）"; final_exit=1
    fi
  fi
else
  r3="skip"; d3="未提供 ENVELOPE_FILE（抓内层信封后重跑）"
fi

emit_evidence
exit "$final_exit"
