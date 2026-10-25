#!/usr/bin/env bash
# deploy-tee-infer-linux.sh - 在 Linux 服务器（含阿里云 TDX 机密 VM）一键部署 tee-infer-service
#
# 前置（在执行前完成）：
#   1) 本机已交叉编译 tee-infer-service Linux 二进制，并连同密钥文件上传到本目录：
#        tee-infer-service            # Linux amd64 二进制
#        cmaas.env                    # CMAAS_URL / CMAAS_API_KEY / CMAAS_MODEL（chmod 600）
#   2) 本脚本以 root 或 sudo 执行。
#
# 用法：
#   sudo bash scripts/deploy-tee-infer-linux.sh [-port 19090] [-src-dir <上传目录>]
#
# 动作：安装到 /opt/tee-infer → 生成 systemd 单元 → 开机自启并启动 → 健康检查
# 密钥经 EnvironmentFile 注入进程环境（不进命令行/进程列表），与 Windows 脚本同策略。
set -euo pipefail

PORT=19090
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -port) PORT="$2"; shift 2 ;;
        -src-dir) SRC_DIR="$2"; shift 2 ;;
        *) echo "未知参数: $1"; exit 1 ;;
    esac
done

INSTALL_DIR=/opt/tee-infer
UNIT=/etc/systemd/system/tee-infer.service
BIN_SRC="$SRC_DIR/tee-infer-service"
ENV_SRC="$SRC_DIR/cmaas.env"

echo "[1/6] 校验上传产物"
[[ -x "$BIN_SRC" ]] || { echo "缺少 Linux 二进制: $BIN_SRC"; exit 1; }
[[ -f "$ENV_SRC" ]] || { echo "缺少密钥文件: $ENV_SRC"; exit 1; }
"$BIN_SRC" -h >/dev/null 2>&1 || true   # 触发版本/帮助，确认可执行

echo "[2/6] 安装二进制与密钥到 $INSTALL_DIR"
install -d -m 0755 "$INSTALL_DIR"
install -m 0755 "$BIN_SRC" "$INSTALL_DIR/tee-infer-service"
install -m 0600 "$ENV_SRC" "$INSTALL_DIR/cmaas.env"

echo "[3/6] 校验 cmaas.env 键（不回显值）"
# shellcheck disable=SC1090
set -a; . "$INSTALL_DIR/cmaas.env"; set +a
: "${CMAAS_URL:?cmaas.env 缺 CMAAS_URL}"
: "${CMAAS_API_KEY:?cmaas.env 缺 CMAAS_API_KEY}"
: "${CMAAS_MODEL:?cmaas.env 缺 CMAAS_MODEL}"
echo "       CMAAS_URL=$CMAAS_URL  CMAAS_MODEL=$CMAAS_MODEL  API_KEY=***${CMAAS_API_KEY: -4}"

# 可选引擎（双路线甲乙并存）：cmaas.env 内额外键控，缺省仅起乙（cmaas）。
#   甲 = 自建 vLLM/llama.cpp：ENGINE_URL=<http://127.0.0.1:8080>
#   双路线策略文件：ROUTE_CONFIG=/opt/tee-infer/route-config.json（deploy/tee-infer/route-config.dual.example.json）
#   飞地实现：ENCLAVE=tdx（真 TDX Quote；缺省 mock）
#   GAP-01/GAP-05：缺省 DEV_MODE=1（开发形态，透传 -dev-mode）；生产须设 DEV_MODE=0
#                  并在 cmaas.env 配置 ADMIN_TOKEN，否则启动守卫拒绝启动。
EXTRA_OPTS=""
if [[ -n "${ENGINE_URL:-}" ]]; then
    EXTRA_OPTS+=" -engine-url=${ENGINE_URL}"
    echo "       甲(自建 vLLM) ENGINE_URL=$ENGINE_URL"
fi
if [[ -n "${ROUTE_CONFIG:-}" ]]; then
    EXTRA_OPTS+=" -route-config=${ROUTE_CONFIG}"
    echo "       双路线策略 ROUTE_CONFIG=$ROUTE_CONFIG"
fi
if [[ -n "${ENCLAVE:-}" ]]; then
    EXTRA_OPTS+=" -enclave=${ENCLAVE}"
    echo "       飞地实现 ENCLAVE=$ENCLAVE"
fi
# 威胁模型 GAP-01/GAP-05：默认 mock 形态须显式 -dev-mode 方可启动。
# 生产（ENCLAVE=tdx）应设 DEV_MODE=0，并在 cmaas.env 配置 ADMIN_TOKEN。
if [[ "${DEV_MODE:-1}" == "1" ]]; then
    EXTRA_OPTS+=" -dev-mode"
    echo "       开发模式 DEV_MODE=1（放行 mock 飞地/空管理令牌；生产请设 DEV_MODE=0）"
fi
if [[ -n "${ADMIN_TOKEN:-}" ]]; then
    # 经 EnvironmentFile 注入，不出现于命令行/进程列表。
    EXTRA_OPTS+=" -admin-token=\${ADMIN_TOKEN}"
    echo "       管理令牌：经 EnvironmentFile 的 ADMIN_TOKEN 注入"
fi

echo "[4/6] 写 systemd 单元（密钥经 EnvironmentFile 注入，不出现在命令行）"
cat > "$UNIT" <<EOF
[Unit]
Description=tee-infer-service (confidential inference, TEE/TDX)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/tee-infer-service -listen :$PORT -cmaas-url=\${CMAAS_URL} -cmaas-model=\${CMAAS_MODEL}$EXTRA_OPTS
EnvironmentFile=$INSTALL_DIR/cmaas.env
Restart=on-failure
RestartSec=3
# 最小权限
NoNewPrivileges=true
ProtectSystem=full
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

echo "[5/6] 重载并启动"
systemctl daemon-reload
systemctl enable tee-infer.service >/dev/null 2>&1 || true
systemctl restart tee-infer.service

echo "[6/6] 健康检查（最多等 30s）"
for i in $(seq 1 15); do
    if curl -sf "http://127.0.0.1:$PORT/healthz/live" >/dev/null 2>&1; then
        echo "OK: tee-infer-service 已就绪 :$PORT"
        systemctl status tee-infer.service --no-pager | head -5 || true
        echo
        echo "下一步："
        echo "  1) 验证 TDX 能力（若为机密实例）：lscpu | grep -i tdx_guest"
        echo "  2) 审计/指标：curl http://127.0.0.1:$PORT/audit"
        echo "  3) 网关接入：Higress 插件 tee_service 指向本机 $(hostname -I | awk '{print $1}'):$PORT"
        exit 0
    fi
    sleep 2
done
echo "FAIL: 30s 内未就绪，查看日志: journalctl -u tee-infer.service -n 50 --no-pager"
exit 1
