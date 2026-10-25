#!/usr/bin/env bash
# setup-linux-env.sh - OTP-Mask 双路线完整 Linux 环境一键搭建
#
# 覆盖路线 1（tee_gpu：TEE 内明文 vLLM）与路线 2（masked_vector：密文向量推理）：
#   系统依赖(含 Go) → Python venv → torch(CUDA/CPU) → triton → numpy
#   → vLLM 源码编译(CUDA/CPU 按设备) → tee-infer 补算服务编译 → 模型下载 → 分路线验证
#
# 用法（root 或 sudo）：
#   bash setup-linux-env.sh --project /opt/security-ai-gateway --vllm-src /opt/vllm
#     --route 1|2|both          [默认 both：两条路线环境都装并验证]
#     --device cuda|auto|cpu    [默认 auto：有 nvidia-smi 则 cuda]
#     --model Qwen/Qwen2.5-1.5B-Instruct   [可选，下载模型]
#     --venv /opt/venv-vllm     [默认 /opt/venv-vllm]
#     --hf-mirror URL           [模型下载镜像，默认 https://hf-mirror.com；none 关闭]
#     --skip-verify             [跳过末尾验证]
#
# 通过标准（route=both）：
#   路线 1：适配器语法 + mock 冒烟 + 双路线路由 Go 测试 + tee-infer /attest 200
#   路线 2：内核测试 21/21 + 核心回归 35/35 + /v1/recompute 补算 Go 集成测试
set -euo pipefail

# ---------- 参数 ----------
PROJECT=""
VLLM_SRC=""
MODEL=""
ROUTE="both"
DEVICE="auto"
VENV="/opt/venv-vllm"
HF_MIRROR="https://hf-mirror.com"
SKIP_VERIFY=0
MIRROR="https://pypi.tuna.tsinghua.edu.cn/simple"
# Go 工具链目标版本（go.mod 要求 go 1.25.0；可用 GO_VERSION 覆盖）
GO_VERSION="${GO_VERSION:-1.25.0}"

usage() {
  sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --project)  PROJECT="$2"; shift 2 ;;
    --vllm-src) VLLM_SRC="$2"; shift 2 ;;
    --model)    MODEL="$2"; shift 2 ;;
    --route)    ROUTE="$2"; shift 2 ;;
    --device)   DEVICE="$2"; shift 2 ;;
    --venv)     VENV="$2"; shift 2 ;;
    --hf-mirror) HF_MIRROR="$2"; shift 2 ;;
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
case "$ROUTE" in 1|2|both) : ;; *) echo "--route 仅支持 1|2|both"; exit 2 ;; esac

if [ "$DEVICE" = "auto" ]; then
  if command -v nvidia-smi >/dev/null && nvidia-smi -L >/dev/null 2>&1; then
    DEVICE="cuda"
  else
    DEVICE="cpu"
  fi
fi
case "$DEVICE" in cuda|cpu) : ;; *) echo "device 仅支持 cuda|cpu|auto"; exit 2 ;; esac

# CUDA 编译预检：vLLM GPU 构建必须 nvcc（缺则快速失败，避免 30 分钟后编译报错）
if [ "$DEVICE" = "cuda" ] && ! command -v nvcc >/dev/null; then
  echo "错误：DEVICE=cuda 但未找到 nvcc（vLLM GPU 编译必需）"
  echo "  安装：apt-get install -y nvidia-cuda-toolkit，或使用 NVIDIA NGC 容器，或 --device cpu"
  exit 1
fi

PY="$VENV/bin/python"
PIP="$VENV/bin/pip"
PASS=0
FAIL=0
say() { printf '\n== %s ==\n' "$1"; }
ok()  { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

# ---------- 1. 系统依赖（Go 工具链单独处理：需 ≥ go.mod 1.25） ----------
say "1/8 系统依赖"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  build-essential cmake ninja-build python3-dev python3-venv \
  libopenblas-dev libgomp1 libaio-dev pkg-config git curl
ok "系统依赖（build-essential/cmake/ninja/python3-dev/openblas/git/curl）"

# Go：go.mod 要求 go 1.25，发行版 golang-go 版本通常滞后。
#  分支：已有满足版本→复用；amd64→官方 tarball 安装（GO_VERSION 可覆盖）；其他架构→提示手装
go_version_ok() {
  local have want
  have="$(command go version 2>/dev/null | awk '{print $3}' | sed 's/go//')"
  want="$1"
  [ -n "$have" ] && [ "$(printf '%s\n%s\n' "$have" "$want" | sort -V | head -1)" = "$want" ]
}
if command -v go >/dev/null 2>&1 && go_version_ok "$GO_VERSION"; then
  ok "Go $(go version | awk '{print $3}')（满足 go.mod $GO_VERSION，PATH 已有）"
elif [ "$(uname -m)" != "x86_64" ]; then
  echo "未内置非 amd64 的 Go 安装；请手动安装 Go $GO_VERSION+（https://go.dev/dl）并加入 PATH" >&2; exit 1
else
  echo "  [INFO] 安装 Go $GO_VERSION（官方 tarball，~80MB）..."
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tgz
  rm -f /tmp/go.tgz
  export PATH="/usr/local/go/bin:$PATH"
  ok "Go 官方安装 $GO_VERSION（$(go version | awk '{print $3}')，已加入 PATH）"
fi

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

# ---------- 4. triton（GPU 内核，两条路线 CUDA 构建均需要） ----------
say "4/8 triton"
if [ "$DEVICE" = "cuda" ]; then
  "$PIP" install -q triton -i "$MIRROR"
  "$PY" -c "import triton; print('  triton', triton.__version__)"
  ok "triton"
else
  echo "  CPU 模式跳过（--with-triton 可手动安装）"
fi

# ---------- 5. vLLM 源码编译 ----------
say "5/8 vLLM 编译（$VLLM_SRC，VLLM_TARGET_DEVICE=$DEVICE）"
"$PIP" install -q setuptools wheel setuptools-scm setuptools-rust -i "$MIRROR"
git config --global --add safe.directory '*' 2>/dev/null || true
export SETUPTOOLS_SCM_PRETEND_VERSION=0.22.1
# 路线 1 需 GPU 版 vLLM（TEE 内明文引擎），路线 2 需 GPU 密文内核：
# 编译目标随 --device 走，cuda 构建约 40-90 分钟（编译全部 CUDA kernel）
VLLM_TARGET_DEVICE="$DEVICE" "$PIP" install -e "$VLLM_SRC" --no-build-isolation -i "$MIRROR" \
  >/tmp/vllm-build.log 2>&1
"$PY" -c "import vllm; print('  vllm', vllm.__version__)"
ok "vLLM 编译安装（$DEVICE）"

# ---------- 6. tee-infer 补算服务编译（Go） ----------
say "6/8 tee-infer 补算服务编译"
(
  cd "$PROJECT/gateway/tee-infer-service"
  go build -o /usr/local/bin/tee-infer-service .
)
[ -x /usr/local/bin/tee-infer-service ] || { echo "tee-infer 编译失败"; exit 1; }
ok "tee-infer-service -> /usr/local/bin/tee-infer-service"

# ---------- 7. 模型下载（可选，走 HF 镜像） ----------
say "7/8 模型下载"
if [ -n "$MODEL" ]; then
  if [ "$HF_MIRROR" != "none" ]; then
    export HF_ENDPOINT="$HF_MIRROR"
    echo "  HF_ENDPOINT=$HF_ENDPOINT"
  fi
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

# ---------- 8. 验证（按路线） ----------
say "8/8 验证（route=$ROUTE）"
if [ "$SKIP_VERIFY" = "1" ]; then
  echo "  跳过（--skip-verify）"
else
  MASKED="$PROJECT/vllm/vllm/masked"
  [ -d "$MASKED" ] || MASKED="$VLLM_SRC/vllm/masked"
  [ "$DEVICE" = "cuda" ] && export VLLM_MASKED_BACKEND=cuda || export VLLM_MASKED_BACKEND=cpu

  # 8.1 tee-infer 冒烟（真实二进制，mock 引擎，/attest 应 200）
  (/usr/local/bin/tee-infer-service -listen :19090 >/tmp/tee-infer-smoke.log 2>&1 &
   sleep 2
   curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:19090/attest >/tmp/tee-http.txt 2>/dev/null || true
   pkill -f tee-infer-service 2>/dev/null || true)
  [ "$(cat /tmp/tee-http.txt 2>/dev/null)" = "200" ] && ok "tee-infer 冒烟 200" || bad "tee-infer 冒烟"

  if [ "$ROUTE" = "1" ] || [ "$ROUTE" = "both" ]; then
    # 8.2 路线 1：适配器语法 + mock 冒烟（/health 应答 engine=mock）
    ADAPTER="$PROJECT/gateway/vllm-adapter/vllm_adapter.py"
    if [ -f "$ADAPTER" ]; then
      if "$PY" -m py_compile "$ADAPTER"; then ok "vllm-adapter 语法"; else bad "vllm-adapter 语法"; fi
      ("$PY" "$ADAPTER" --mock --listen 127.0.0.1:19190 >/tmp/vllm-adapter-smoke.log 2>&1 &
       sleep 1
       curl -s http://127.0.0.1:19190/health >/tmp/adapter-health.txt 2>/dev/null || true
       pkill -f 'vllm_adapter.py --mock' 2>/dev/null || true)
      grep -qE '"status": *"ok"' /tmp/adapter-health.txt 2>/dev/null \
        && ok "vllm-adapter mock 冒烟" || bad "vllm-adapter mock 冒烟"
    else
      bad "vllm-adapter 缺失: $ADAPTER"
    fi
    # 8.3 路线 1：双路线路由 + 引擎接线（Go 集成测试）
    if (cd "$PROJECT" && go test ./gateway/tee-infer-service/ -run 'TestDualRoute|TestRoute' -count=1 >/tmp/route1-test.log 2>&1); then
      ok "双路线路由测试（TestDualRoute/TestRoute）"
    else
      bad "双路线路由测试（详见 /tmp/route1-test.log）"
    fi
  fi

  if [ "$ROUTE" = "2" ] || [ "$ROUTE" = "both" ]; then
    # 8.4 路线 2：内核测试（多后端密文 GEMM parity）
    [ -d "$MASKED" ] || { echo "未找到 masked 包"; exit 1; }
    if "$PY" "$MASKED/kernels/test_gemm.py"; then ok "test_gemm 21/21"; else bad "test_gemm"; fi
    # 8.5 路线 2：核心回归（cipher_core 语义对齐）
    if "$PY" "$MASKED/test_masked_core.py"; then ok "test_masked_core 35/35"; else bad "test_masked_core"; fi
    # 8.6 路线 2：/v1/recompute 补算全流程（证明会话+签名+层序，Go 集成测试）
    if (cd "$PROJECT" && go test ./gateway/tee-infer-service/ -run 'TestRecomputeE2E|TestRecomputeRMSNormArgMax' -count=1 >/tmp/recompute-test.log 2>&1); then
      ok "补算端点 /v1/recompute（会话+签名+层序）"
    else
      bad "补算端点测试（详见 /tmp/recompute-test.log）"
    fi
  fi
fi

# ---------- 汇总 ----------
say "汇总"
echo "  ROUTE=$ROUTE DEVICE=$DEVICE PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -eq 0 ]; then
  echo "环境搭建完成。启动方式："
  echo "  补算服务: tee-infer-service -listen :19090"
  if [ "$ROUTE" = "1" ] || [ "$ROUTE" = "both" ]; then
    echo "  路线 1（tee_gpu 明文引擎）:"
    echo "    python $PROJECT/gateway/vllm-adapter/vllm_adapter.py --model <模型路径> --listen :19190"
    echo "    tee-infer-service -listen :19090 -engine-url http://127.0.0.1:19190"
    echo "    （生产形态需 GPU TEE：NVIDIA CC 模式容器/驱动开启机密计算）"
  fi
  if [ "$ROUTE" = "2" ] || [ "$ROUTE" = "both" ]; then
    echo "  路线 2（masked_vector 密文模式）:"
    echo "    export VLLM_MASKED_ENGINE_TYPE=masked_vector VLLM_MASKED_TEE_URL=http://127.0.0.1:19090"
  fi
  exit 0
else
  echo "存在失败项，请查上文输出（测试日志在 /tmp/*.log）"
  exit 1
fi
