#!/usr/bin/env bash
# setup-env.sh - OTP-Mask 安全 AI 网关一键环境搭建（Linux 生产/开发）
#
# 流程：工具检查/安装 → GOPROXY → 全量构建（含 wasm 插件）→ 启动容器 → 验证套件
#
# 用法：
#   bash scripts/setup-env.sh                 # 完整流程（构建+启动+验证）
#   bash scripts/setup-env.sh --skip-verify   # 跳过验证套件
#   bash scripts/setup-env.sh --with-k8s      # 额外检查 kubectl/helm
#
# 依赖：Ubuntu/Debian（apt）或 CentOS/RHEL（yum）；Docker 20+ + Compose；Go 1.25+（go.mod 要求）；Python 3.10+
# 验证套件使用 pwsh（PowerShell Core）——未安装时提示或跳过。

set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKIP_VERIFY=0
WITH_K8S=0
for arg in "$@"; do
  case "$arg" in
    --skip-verify) SKIP_VERIFY=1 ;;
    --with-k8s) WITH_K8S=1 ;;
  esac
done

say_ok() { echo "[PASS] $1"; }
say_fail() { echo "[FAIL] $1"; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

echo "===== OTP-Mask 环境搭建（Linux） ====="

# 1. 工具检查（缺则按发行版安装）
echo ""
echo "[1/6] 工具检查"
INSTALL_CMD=""
if has_cmd apt-get; then INSTALL_CMD="apt-get install -y"; fi
if has_cmd yum; then INSTALL_CMD="yum install -y"; fi

for tool in git docker; do
  if has_cmd "$tool"; then
    say_ok "$tool 已安装"
  else
    say_fail "$tool 缺失（sudo $INSTALL_CMD $tool）"
    [ -n "$INSTALL_CMD" ] && { echo "[INFO] 尝试安装 $tool ..."; sudo $INSTALL_CMD "$tool"; }
  fi
done

# docker compose 插件检测（第 5 步使用 `docker compose`；缺失时回退 docker-compose v1）
COMPOSE_CMD="docker compose"
if has_cmd docker; then
  if docker compose version >/dev/null 2>&1; then
    say_ok "docker compose 插件可用"
  elif has_cmd docker-compose; then
    say_ok "docker-compose（v1）可用"
    COMPOSE_CMD="docker-compose"
  else
    say_fail "docker compose 插件缺失——请安装 Docker Compose v2 插件（https://docs.docker.com/compose/install/）"
  fi
fi

# Go 版本：go.mod 要求 go 1.25.0，需显式校验（发行版 golang-go 版本通常滞后）
GO_TOO_OLD=0
go_version_ok() {
  local have want
  have="$(command go version 2>/dev/null | awk '{print $3}' | sed 's/go//')"
  want="$1"
  [ -n "$have" ] && [ "$(printf '%s\n%s\n' "$have" "$want" | sort -V | head -1)" = "$want" ]
}
if has_cmd go; then
  if go_version_ok 1.25; then
    say_ok "go 已安装（$(go version | awk '{print $3}')，满足 go.mod 1.25）"
  else
    say_fail "go 版本 $(go version | awk '{print $3}') 低于 go.mod 要求的 1.25"
    GO_TOO_OLD=1
  fi
else
  say_fail "go 缺失（请安装 Go 1.25+：https://go.dev/dl）"
  GO_TOO_OLD=1
fi
if has_cmd python3; then
  say_ok "python3 已安装"
else
  say_fail "python3 缺失"
fi
if [ "$WITH_K8S" = "1" ]; then
  for tool in kubectl helm; do
    has_cmd "$tool" && say_ok "$tool 已安装" || say_fail "$tool 缺失（可选）"
  done
fi

# 2. Go 环境
echo ""
echo "[2/6] Go 环境"
if [ "$GO_TOO_OLD" = "1" ]; then
  >&2 echo "[ERROR] Go 不足或缺失，中止部署。请安装 Go 1.25+（https://go.dev/dl/）后重试"
  exit 1
fi
go env -w GOPROXY=https://goproxy.cn,direct
say_ok "GOPROXY=https://goproxy.cn,direct"

# 3. 全量构建（含 wasm 插件）
echo ""
echo "[3/6] 全量构建"
cd "$ROOT"
go build ./...
GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared \
  -o gateway/wasm/otpmask-plugin/main.wasm ./gateway/wasm/otpmask-plugin
say_ok "Go 全量构建 + wasm 插件构建完成"

# 4. Python 检查
echo ""
echo "[4/6] Python 检查"
PYTHON="${PYTHON_BIN:-python3}"
"$PYTHON" -c "import sys; sys.path.insert(0, 'protocol/python'); import otpmask_protocol; print('[PASS] otpmask_protocol 可导入')"

# 5. 启动容器
echo ""
echo "[5/6] 启动容器"
cd "$ROOT/gateway/wasm/otpmask-plugin"
$COMPOSE_CMD up -d --build
sleep 6
say_ok "容器已启动（网关 10000 / embedding 18080 / tee-infer 19090）"
cd "$ROOT"

# 6. 验证套件（pwsh）
if [ "$SKIP_VERIFY" = "1" ]; then
  echo ""
  echo "[6/6] 跳过验证（--skip-verify）"
else
  echo ""
  echo "[6/6] 验证套件"
  if has_cmd pwsh; then
    pwsh -NoProfile -File scripts/verify-all.ps1 || say_fail "验证套件未全过"
  else
    echo "[INFO] 未安装 pwsh，跳过验证套件（安装：https://github.com/PowerShell/PowerShell/releases）"
    echo "      或手动验证：go test ./... && python protocol/python/cross_test.py"
  fi
fi

echo ""
echo "===== 完成 ====="
echo "访问入口："
echo "  推理（SSE）: http://127.0.0.1:10000/infer"
echo "  治理/指标:   http://127.0.0.1:19090/usage | /audit/verify | /metrics"
echo "  （GPU 环境接真实 vLLM：pwsh -File scripts/vllm-up.ps1 -Mode Gpu，或 python gateway/vllm-adapter/vllm_adapter.py --model ...）"
