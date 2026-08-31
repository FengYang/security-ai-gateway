#!/usr/bin/env bash
# setup-linux-env.sh - OTP-Mask 路线2 完整 Linux 环境一键搭建
#
# 覆盖全链路：
#   系统依赖(含 Go) → Python venv → torch(CUDA/CPU) → triton → numpy
#   → vLLM 源码编译 → tee-infer 补算服务编译 → 模型下载 → 内核验证
#
# 用法（root 或 sudo）：
#   bash setup-linux-env.sh --project /opt/security-ai-gateway --vllm-src /opt/vllm
#     --device cuda|auto|cpu   [默认 auto：有 nvidia-smi 则 cuda]
#     --model Qwen/Qwen2.5-1.5B-Instruct   [可选，下载模型]
#     --venv /opt/venv-vllm    [默认 /opt/venv-vllm]
#     --skip-verify            [跳过末尾验证]
#
# 通过标准：内核测试 21/21 + 核心回归 35/35 + tee-infer 冒烟 200
set -euo pipefail

# ---------- 参数 ----------
PROJECT=""
VLLM_SRC=""
MODEL=""
DEVICE="auto"
VENV="/opt/venv-vllm"
SKIP_VERIFY=0
MIRROR="https://pypi.tuna.tsinghua.edu.cn/simple"

usage() {
  sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --project)  PROJECT="$2"; shift 2 ;;
    --vllm-src) VLLM_SRC="$2"; shift 2 ;;
    --model)    MODEL="$2"; shift 2 ;;
    --device)   DEVICE="$2"; shift 2 ;;
    --venv)     VENV="$2"; shift 2 ;;
    --skip-verify) SKIP_VERIFY=1; shift ;;
    -h|--help)  usage ;;
    *) echo "未知参数: $1"; usage ;;
  esac
done

[ -n "$PROJECT" ]  || { echo "必须指定 --project（security-ai-gateway 源码路径）"; usage; }
[ -n "$VLLM_SRC" ] || { echo "必须指定 --vllm-src（vLLM 源码路径）"; usage; }
[ -d "$PROJECT/gateway/tee-infer-service" ] || { echo "无效项目路径: $PROJECT"; exit 1; }
[ -f "$VLLM_SRC/pyproject.toml" ] || { echo "无效 vLLM 路径: $VLLM_SRC"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "请用 root 或 sudo 执行"; exit 1; }

if [ "$DEVICE" = "auto" ]; then
  if command -v nvidia-smi >/dev/null && nvidia-smi -L >/dev/null 2>&1; then
    DEVICE="cuda"
  else
    DEVICE="cpu"
  fi
fi
case "$DEVICE" in cuda|cpu) : ;; *) echo "device 仅支持 cuda|cpu|auto"; exit 2 ;; esac

PY="$VENV/bin/python"
PIP="$VENV/bin/pip"
PASS=0
FAIL=0
say() { printf '\n== %s ==\n' "$1"; }
ok()  { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

# ---------- 1. 系统依赖（含 Go 工具链） ----------
say "1/8 系统依赖"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  build-essential cmake ninja-build python3-dev python3-venv \
  libopenblas-dev libgomp1 libaio-dev pkg-config git curl golang-go
command -v go >/dev/null || { echo "Go 安装失败"; exit 1; }
ok "系统依赖 + Go $(go version | awk '{print $3}')"

# ---------- 2. venv + 基础 Python 依赖 ----------
say "2/8 venv 与基础依赖"
if [ ! -x "$PY" ]; then
  python3 -m venv "$VENV"
  "$PIP" install -q -U pip -i "$MIRROR"
fi
"$PIP" install -q numpy huggingface_hub -i "$MIRROR"
ok "venv $VENV"

# ---------- 3. torch（CUDA / CPU 分支） ----------
say "3/8 torch（device=$DEVICE）"
if [ "$DEVICE" = "cuda" ]; then
  "$PIP" install -q torch --index-url https://download.pytorch.org/whl/cu130 \
    || "$PIP" install -q torch -i "$MIRROR"   # 镜像兜底
else
  "$PIP" install -q torch==2.13.0 --index-url https://download.pytorch.org/whl/cpu
fi
"$PY" -c "import torch; print('  torch', torch.__version__)"
ok "torch($DEVICE)"

# ---------- 4. triton（GPU 平台内核） ----------
say "4/8 triton"
if [ "$DEVICE" = "cuda" ]; then
  "$PIP" install -q triton -i "$MIRROR"
  "$PY" -c "import triton; print('  triton', triton.__version__)"
  ok "triton"
else
  echo "  CPU 模式跳过（--with-triton 可手动安装）"
fi

# ---------- 5. vLLM 源码编译 ----------
say "5/8 vLLM 编译（$VLLM_SRC，约 20-40 分钟）"
"$PIP" install -q setuptools wheel setuptools-scm setuptools-rust -i "$MIRROR"
git config --global --add safe.directory '*' 2>/dev/null || true
export SETUPTOOLS_SCM_PRETEND_VERSION=0.22.1
VLLM_TARGET_DEVICE=cpu "$PIP" install -e "$VLLM_SRC" --no-build-isolation -i "$MIRROR" \
  >/tmp/vllm-build.log 2>&1
"$PY" -c "import vllm; print('  vllm', vllm.__version__)"
ok "vLLM 编译安装"

# ---------- 6. tee-infer 补算服务编译（Go） ----------
say "6/8 tee-infer 补算服务编译"
(
  cd "$PROJECT/gateway/tee-infer-service"
  go build -o /usr/local/bin/tee-infer-service .
)
[ -x /usr/local/bin/tee-infer-service ] || { echo "tee-infer 编译失败"; exit 1; }
ok "tee-infer-service -> /usr/local/bin/tee-infer-service"

# ---------- 7. 模型下载（可选） ----------
say "7/8 模型下载"
if [ -n "$MODEL" ]; then
  "$PY" - "$MODEL" <<'EOF'
import sys
from huggingface_hub import snapshot_download
p = snapshot_download(sys.argv[1])
print("  model at:", p)
EOF
  ok "模型 $MODEL"
else
  echo "  跳过（未指定 --model）"
fi

# ---------- 8. 验证 ----------
say "8/8 验证"
if [ "$SKIP_VERIFY" = 1 ]; then
  echo "  跳过（--skip-verify）"
else
  MASKED="$PROJECT/vllm/vllm/masked"
  [ -d "$MASKED" ] || MASKED="$VLLM_SRC/vllm/masked"
  [ -d "$MASKED" ] || { echo "未找到 masked 包"; exit 1; }
  [ "$DEVICE" = "cuda" ] && export VLLM_MASKED_BACKEND=cuda || export VLLM_MASKED_BACKEND=cpu

  # 8.1 内核测试
  if "$PY" "$MASKED/kernels/test_gemm.py"; then ok "test_gemm 21/21"; else bad "test_gemm"; fi
  # 8.2 核心回归
  if "$PY" "$MASKED/test_masked_core.py"; then ok "test_masked_core 35/35"; else bad "test_masked_core"; fi
  # 8.3 tee-infer 冒烟（mock 引擎，纯 CPU 起服务，/attest 应 200）
  (/usr/local/bin/tee-infer-service -listen :19090 >/tmp/tee-infer-smoke.log 2>&1 &
   sleep 2
   curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:19090/attest >/tmp/tee-http.txt 2>/dev/null || true
   pkill -f tee-infer-service 2>/dev/null || true)
  [ "$(cat /tmp/tee-http.txt 2>/dev/null)" = "200" ] && ok "tee-infer 冒烟 200" || bad "tee-infer 冒烟"
fi

# ---------- 汇总 ----------
say "汇总"
echo "  PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -eq 0 ]; then
  echo "环境搭建完成。启动补算服务: tee-infer-service -listen :19090"
  echo "密文模式启用: export VLLM_MASKED_ENGINE_TYPE=masked_vector VLLM_MASKED_TEE_URL=http://127.0.0.1:19090"
  exit 0
else
  echo "存在失败项，请查上文输出"
  exit 1
fi
