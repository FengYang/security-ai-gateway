#!/usr/bin/env bash
# gen-ca.sh — P2-4 remote-write mTLS 证书生成器（**离线**，不联网、不依赖 K8s）
#
# 两种模式：
#   self-signed（默认）内置自签 CA：生成 CA + 服务端证书 + 客户端证书，POC/内网即用
#   csr               企业 CA 流程：只生成私钥与 CSR，交由客户 CA 签发（我方不持有 CA 私钥）
#
# 产物（--out 指定目录，权限 0700，私钥 0600）：
#   self-signed: ca.crt ca.key  server.crt server.key  client.crt client.key
#   csr        : server.csr server.key  client.csr client.key  （签发后放回 server.crt / client.crt / ca.crt）
#
# 口径（与 deploy/monitoring-overlays/remote-write-mtls/README.md、附录 §5 PRE-D-3 一致）：
#   * 服务端证书 SAN 必须覆盖发送侧配置的 `tls_config.server_name`
#   * 服务端 EKU=serverAuth，客户端 EKU=clientAuth（**用途分离，不签双用途证书**）
#   * 有效期默认 90 天（轮换周期口径）；`--days` 可改，>90 会告警
#   * 私钥**只落盘不入库**；Secret 由 kubectl 创建（脚本只打印命令，不执行）
#   * 已存在产物时**拒绝覆盖**（需 --force，且会先重命名为 .bak-<时间戳>）
#
# 退出码：0 成功｜2 参数/环境错误｜3 前置不满足（目录非空且未 --force 等）
#
# 用法：
#   ./gen-ca.sh --out ./certs
#   ./gen-ca.sh --out ./certs --server-san prometheus-central.otpmask.svc.cluster.local,central.example.com
#   ./gen-ca.sh --out ./certs --mode csr --days 365
#   ./gen-ca.sh --out ./certs --force          # 重签（旧产物移到 .bak-<ts>）

set -euo pipefail

umask 077

OUT_DIR=""
MODE="self-signed"
SERVER_SAN="prometheus-central.otpmask.svc.cluster.local,prometheus-central.otpmask.svc,localhost"
DAYS=90
FORCE=0
KEY_TYPE="ecdsa"

usage() {
  cat <<'EOF'
用法：gen-ca.sh --out <dir> [选项]

必选：
  --out <dir>              证书输出目录（不存在则创建；已存在且有产物 → 拒绝，需 --force）

可选：
  --mode self-signed|csr   默认 self-signed（内置自签 CA）；csr＝只生成 CSR 交企业 CA 签发
  --server-san <list>      服务端证书 SAN，逗号分隔
                           默认 prometheus-central.otpmask.svc.cluster.local,
                                prometheus-central.otpmask.svc,localhost
  --days <n>               证书有效期天数（默认 90；>90 会告警）
  --key-type ecdsa|rsa     私钥类型（默认 ecdsa P-256；rsa＝2048）
  --force                  覆盖已有产物（先把旧文件移到 .bak-<时间戳>）
  -h|--help                本帮助

产物：
  self-signed → ca.crt ca.key server.crt server.key client.crt client.key
  csr         → server.csr server.key client.csr client.key

安全红线：
  * 私钥 0600、目录 0700，**禁止入库**
  * 本脚本不联网、不调用 kubectl；Secret 命令由脚本打印，人工执行
EOF
}

die_args() { echo "参数错误：$1" >&2; usage >&2; exit 2; }
die_env() { echo "环境不满足：$1" >&2; exit 3; }

while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT_DIR="${2:-}"; shift 2 ;;
    --out=*) OUT_DIR="${1#*=}"; shift ;;
    --mode) MODE="${2:-}"; shift 2 ;;
    --mode=*) MODE="${1#*=}"; shift ;;
    --server-san) SERVER_SAN="${2:-}"; shift 2 ;;
    --server-san=*) SERVER_SAN="${1#*=}"; shift ;;
    --days) DAYS="${2:-}"; shift 2 ;;
    --days=*) DAYS="${1#*=}"; shift ;;
    --key-type) KEY_TYPE="${2:-}"; shift 2 ;;
    --key-type=*) KEY_TYPE="${1#*=}"; shift ;;
    --force) FORCE=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die_args "未知参数：$1" ;;
  esac
done

[ -n "$OUT_DIR" ] || die_args "--out 必填"
case "$MODE" in self-signed | csr) ;; *) die_args "--mode 必须是 self-signed 或 csr（收到 '$MODE'）" ;; esac
case "$KEY_TYPE" in ecdsa | rsa) ;; *) die_args "--key-type 必须是 ecdsa 或 rsa（收到 '$KEY_TYPE'）" ;; esac
case "$DAYS" in '' | *[!0-9]*) die_args "--days 必须是正整数" ;; esac
[ "$DAYS" -ge 1 ] || die_args "--days 必须 >= 1"
[ -n "$SERVER_SAN" ] || die_args "--server-san 不能为空"

command -v openssl >/dev/null 2>&1 || die_env "未找到 openssl（需 OpenSSL 1.1.1+）"

# ---------- 输出目录：已存在且有产物 → 拒绝（fail-closed，防误覆盖 CA 私钥） ----------
PRODUCTS_SELF="ca.crt ca.key server.crt server.key client.crt client.key"
PRODUCTS_CSR="server.csr server.key client.csr client.key"
if [ "$MODE" = "self-signed" ]; then CHECK_LIST="$PRODUCTS_SELF"; else CHECK_LIST="$PRODUCTS_CSR"; fi

existing=""
for f in $CHECK_LIST; do
  [ -e "$OUT_DIR/$f" ] && existing="$existing $f"
done
if [ -n "$existing" ]; then
  if [ "$FORCE" -ne 1 ]; then
    die_env "$OUT_DIR 已存在产物：$existing —— 拒绝覆盖（CA 私钥重签会使现有证书全部失效）；确需重签请加 --force"
  fi
  BAK="$OUT_DIR/.bak-$(date +%Y%m%dT%H%M%S)"
  mkdir -p "$BAK"
  for f in $CHECK_LIST; do [ -e "$OUT_DIR/$f" ] && mv "$OUT_DIR/$f" "$BAK/"; done
  echo "已备份旧产物 → $BAK"
fi

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR" 2>/dev/null || true

# ---------- 临时 openssl 配置（兼容旧版 openssl，避免依赖 -addext） ----------
# ★ 必须建在 $OUT_DIR 内：Windows 版 openssl 不认 Git Bash 的 /tmp（mktemp -d 的默认位置），
#   配置读不到会导致 SAN/EKU 静默丢失（证书看似生成成功、实际不可用）。
TMPDIR_OSSL="$OUT_DIR/.ossl-tmp-$$"
mkdir -p "$TMPDIR_OSSL"
cleanup() { rm -rf "$TMPDIR_OSSL" 2>/dev/null || true; }
trap cleanup EXIT

# 把逗号分隔 SAN 转成 openssl 单行形式（DNS:a,DNS:b）。
# ★ 不用 `subjectAltName = @alt` 段引用：脚本内 heredoc 生成的段名在部分 openssl 版本下
#   不被 -extfile 解析（实测 SAN 会静默只剩最后一项），单行写法无此风险。
SAN_LINE=""
_ifs_save="$IFS"; IFS=','
for _s in $SERVER_SAN; do
  _s="$(printf '%s' "$_s" | tr -d '[:space:]')"
  [ -n "$_s" ] || continue
  if [ -n "$SAN_LINE" ]; then SAN_LINE="$SAN_LINE,DNS:$_s"; else SAN_LINE="DNS:$_s"; fi
done
IFS="$_ifs_save"
[ -n "$SAN_LINE" ] || die_args "--server-san 解析后为空"

cat >"$TMPDIR_OSSL/ca.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
CN = otpmask-remote-write-ca
O = OTPmask
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

cat >"$TMPDIR_OSSL/server.cnf" <<EOF
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no
[dn]
CN = prometheus-central
O = OTPmask
[v3_req]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = $SAN_LINE
EOF

cat >"$TMPDIR_OSSL/client.cnf" <<'EOF'
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no
[dn]
CN = otpmask-prometheus-writer
O = OTPmask
[v3_req]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
EOF

genkey() { # genkey <out.key>
  if [ "$KEY_TYPE" = "ecdsa" ]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null
  else
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1" 2>/dev/null
  fi
  chmod 600 "$1" 2>/dev/null || true
}

# 私钥权限断言：POSIX 上必须 600；Windows 文件系统不支持 POSIX 权限 → 明确告警（不假装通过）
check_key_perm() {
  local f="$1" mode
  [ -e "$f" ] || return 0
  mode="$(stat -c %a "$f" 2>/dev/null || stat -f %Lp "$f" 2>/dev/null || echo '')"
  [ -n "$mode" ] || return 0
  [ "$mode" = "600" ] && return 0
  case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW* | MSYS* | CYGWIN*)
      echo "  ⚠ $(basename "$f") 权限 $mode（Windows 文件系统无 POSIX 权限语义）→ 请在 Linux 上重新生成，或自行加密保管" >&2
      return 0
      ;;
    *)
      echo "  ✗ $(basename "$f") 权限 $mode，应为 600（私钥不可被同组/其他用户读取）" >&2
      return 1
      ;;
  esac
}

echo "== 生成私钥（${KEY_TYPE}）=="
genkey "$OUT_DIR/server.key"
genkey "$OUT_DIR/client.key"

echo "== 生成服务端 CSR =="
openssl req -new -key "$OUT_DIR/server.key" -out "$OUT_DIR/server.csr" -config "$TMPDIR_OSSL/server.cnf" 2>/dev/null

echo "== 生成客户端 CSR =="
openssl req -new -key "$OUT_DIR/client.key" -out "$OUT_DIR/client.csr" -config "$TMPDIR_OSSL/client.cnf" 2>/dev/null

if [ "$MODE" = "csr" ]; then
  # 企业 CA 模式：不生成 CA、不签发；CSR 交客户 CA
  rm -f "$OUT_DIR/server.csr".tmp 2>/dev/null || true
  echo
  echo "== 企业 CA 模式（csr）：CSR 已生成，尚未签发 =="
  echo "  服务端 CSR：$OUT_DIR/server.csr（SAN：$(printf '%s' "$SERVER_SAN" | tr ',' ' ')）"
  echo "  客户端 CSR：$OUT_DIR/client.csr（EKU=clientAuth）"
  echo
  echo "后续（由客户 CA 管理员执行）："
  echo "  1) 用企业 CA 签发两份 CSR，有效期建议 ≤ ${DAYS} 天"
  echo "  2) 把签发结果放回：$OUT_DIR/server.crt、$OUT_DIR/client.crt、$OUT_DIR/ca.crt"
  echo "  3) 校验链：openssl verify -CAfile $OUT_DIR/ca.crt $OUT_DIR/server.crt $OUT_DIR/client.crt"
  echo "  4) 校验 SAN：openssl x509 -in $OUT_DIR/server.crt -noout -ext subjectAltName"
  echo
  echo "⚠️ 服务端证书 SAN 必须覆盖发送侧 tls_config.server_name，否则握手必失败。"
  exit 0
fi

echo "== 生成自签 CA =="
genkey "$OUT_DIR/ca.key"
openssl req -x509 -new -key "$OUT_DIR/ca.key" -out "$OUT_DIR/ca.crt" \
  -days "$DAYS" -config "$TMPDIR_OSSL/ca.cnf" -extensions v3_ca 2>/dev/null

echo "== 签发服务端证书（EKU=serverAuth）=="
openssl x509 -req -in "$OUT_DIR/server.csr" -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" \
  -CAcreateserial -out "$OUT_DIR/server.crt" -days "$DAYS" \
  -extfile "$TMPDIR_OSSL/server.cnf" -extensions v3_req 2>/dev/null

echo "== 签发客户端证书（EKU=clientAuth）=="
openssl x509 -req -in "$OUT_DIR/client.csr" -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" \
  -CAcreateserial -out "$OUT_DIR/client.crt" -days "$DAYS" \
  -extfile "$TMPDIR_OSSL/client.cnf" -extensions v3_req 2>/dev/null

# ---------- 自校验（链 + 用途 + SAN）----------
echo "== 自校验 =="
fail=0
if ! openssl verify -CAfile "$OUT_DIR/ca.crt" "$OUT_DIR/server.crt" >/dev/null 2>&1; then
  echo "  ✗ 服务端证书链校验失败" >&2; fail=1
else
  echo "  ✓ 服务端证书链 OK"
fi
if ! openssl verify -CAfile "$OUT_DIR/ca.crt" "$OUT_DIR/client.crt" >/dev/null 2>&1; then
  echo "  ✗ 客户端证书链校验失败" >&2; fail=1
else
  echo "  ✓ 客户端证书链 OK"
fi
SAN_TEXT="$(openssl x509 -in "$OUT_DIR/server.crt" -noout -ext subjectAltName 2>/dev/null || true)"
san_missing=""
_ifs_save="$IFS"; IFS=','
for _s in $SERVER_SAN; do
  _s="$(printf '%s' "$_s" | tr -d '[:space:]')"
  [ -n "$_s" ] || continue
  printf '%s' "$SAN_TEXT" | grep -q "DNS:$_s" || san_missing="$san_missing $_s"
done
IFS="$_ifs_save"
if [ -z "$san_missing" ] && printf '%s' "$SAN_TEXT" | grep -q "DNS:"; then
  echo "  ✓ 服务端 SAN 覆盖全部 server_name：$(printf '%s' "$SERVER_SAN" | tr ',' ' ')"
else
  echo "  ✗ 服务端证书 SAN 缺失：$san_missing（发送侧 server_name 校验会失败）" >&2; fail=1
fi
# EKU 断言按 openssl 实际输出匹配（"TLS Web Client Authentication" / "clientAuth" 两种写法都要认）
SEKU="$(openssl x509 -in "$OUT_DIR/server.crt" -noout -ext extendedKeyUsage 2>/dev/null || true)"
if printf '%s' "$SEKU" | grep -qiE "server[[:space:]]*auth"; then
  echo "  ✓ 服务端 EKU 含 serverAuth"
else
  echo "  ✗ 服务端证书 EKU 缺 serverAuth" >&2; fail=1
fi
EKUS="$(openssl x509 -in "$OUT_DIR/client.crt" -noout -ext extendedKeyUsage 2>/dev/null || true)"
if printf '%s' "$EKUS" | grep -qiE "client[[:space:]]*auth"; then
  echo "  ✓ 客户端 EKU 含 clientAuth"
else
  echo "  ✗ 客户端证书 EKU 缺 clientAuth" >&2; fail=1
fi
# 私钥权限（POSIX 600；Windows 告警）
for k in "$OUT_DIR/ca.key" "$OUT_DIR/server.key" "$OUT_DIR/client.key"; do
  check_key_perm "$k" || fail=1
done

if [ "$fail" -ne 0 ]; then
  echo "自校验失败：产物**不可用**，请检查 openssl 版本（需 1.1.1+）" >&2
  exit 2
fi

if [ "$DAYS" -gt 90 ]; then
  echo "⚠️ 有效期 ${DAYS} 天 > 90 天口径：请确认这是有意的（默认轮换周期 90 天）"
fi

# ---------- 打印装配命令（不执行） ----------
cat <<EOF

== 产物 ==
  $OUT_DIR/ca.crt      $OUT_DIR/ca.key
  $OUT_DIR/server.crt  $OUT_DIR/server.key
  $OUT_DIR/client.crt  $OUT_DIR/client.key

== 装配（人工执行；私钥禁止入库）==
  # ① 发送侧（各集群 Prometheus）客户端证书 Secret：
  kubectl -n otpmask create secret generic otpmask-remote-write-mtls \\
    --cert=$OUT_DIR/client.crt --key=$OUT_DIR/client.key --ca-file=$OUT_DIR/ca.crt \\
    --dry-run=client -o yaml | kubectl apply -f -

  # ② 接收侧 mTLS 终止代理：需要 ca.crt（校验客户端）+ server.crt/server.key
  #    证书放到代理的证书目录，server_name 必须等于下列 SAN 之一：
  $(printf '%s' "$SERVER_SAN" | tr ',' '\n' | sed 's/^/    - /')

== 轮换 ==
  有效期 ${DAYS} 天。轮换前用 --force 重签会把旧文件备份到 .bak-<ts>；
  生产轮换请**两套证书并存**，先换一端、验证连通，再撤旧端。
EOF
