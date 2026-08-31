#!/usr/bin/env bash
# verify-linux-masked.sh - Linux 密文内核验证环境一键启动
#
# 用途：按 docs/GA-GPU密文内核Linux验证指南.md 自动化验证
#   vllm/vllm/masked/kernels 多后端密文 GEMM。
#
# 用法：
#   bash verify-linux-masked.sh                          # CPU 路径（任何 Linux）
#   bash verify-linux-masked.sh --with-triton            # + Triton（GPU 主机）
#   bash verify-linux-masked.sh --with-vllm /opt/vllm    # + vLLM 集成（装 vLLM）
#   bash verify-linux-masked.sh --backend rocm           # 显式指定平台
#
# 通过标准：test_gemm 21/21 + test_masked_core 35/35（Triton 环境内核路径自动生效）
set -euo pipefail

# ---------- 参数 ----------
VENV=${VENV:-/opt/venv-vllm}
BACKEND=""
WITH_TRITON=0
WITH_VLLM=""
MIRROR="https://pypi.tuna.tsinghua.edu.cn/simple"

while [ $# -gt 0 ]; do
  case "$1" in
    --venv) VENV="$2"; shift 2 ;;
    --with-triton) WITH_TRITON=1; shift ;;
    --with-vllm) WITH_VLLM="${2:-}"; shift 2 ;;
    --backend) BACKEND="$2"; shift 2 ;;
    *) echo "未知参数: $1"; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MASKED_DIR="$ROOT/vllm/vllm/masked"
PY="$VENV/bin/python"
PIP="$VENV/bin/pip"
PASS=0
FAIL=0

say()  { printf '\n== %s ==\n' "$1"; }
ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

check() { # check <名称> <命令...>
  if "$@" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi
}

# ---------- 1. 环境检查 ----------
say "1/6 环境检查"
[ -d "$MASKED_DIR" ] || { echo "未找到 masked 包: $MASKED_DIR（请确认项目路径）"; exit 1; }
command -v python3 >/dev/null || { echo "缺少 python3"; exit 1; }

# ---------- 2. venv + 依赖 ----------
say "2/6 venv 与依赖"
if [ ! -x "$PY" ]; then
  python3 -m venv "$VENV"
  "$PIP" install -q -U pip -i "$MIRROR"
fi
"$PIP" install -q numpy -i "$MIRROR"
[ "$WITH_TRITON" = 1 ] && "$PIP" install -q triton -i "$MIRROR"

# ---------- 3. vLLM（可选） ----------
say "3/6 vLLM 安装（--with-vllm）"
if [ -n "$WITH_VLLM" ]; then
  if [ ! -f "$WITH_VLLM/pyproject.toml" ]; then
    echo "vLLM 源码路径无效: $WITH_VLLM"; exit 1
  fi
  "$PIP" install -q setuptools wheel setuptools-scm setuptools-rust -i "$MIRROR"
  git config --global --add safe.directory '*' 2>/dev/null || true
  export SETUPTOOLS_SCM_PRETEND_VERSION=0.22.1
  (cd "$WITH_VLLM" && VLLM_TARGET_DEVICE=cpu \
    "$PIP" install -e . --no-build-isolation -i "$MIRROR" >/dev/null 2>&1)
  ok "vLLM installed at $WITH_VLLM"
else
  echo "  跳过（未指定 --with-vllm）"
fi

# ---------- 4. 内核单元测试 ----------
say "4/6 密文内核测试（test_gemm）"
[ -n "$BACKEND" ] && export VLLM_MASKED_BACKEND="$BACKEND"
if "$PY" "$MASKED_DIR/kernels/test_gemm.py"; then ok "test_gemm 21/21"; else bad "test_gemm"; fi

# ---------- 5. 核心包回归 ----------
say "5/6 核心包回归（test_masked_core）"
if "$PY" "$MASKED_DIR/test_masked_core.py"; then ok "test_masked_core 35/35"; else bad "test_masked_core"; fi

# ---------- 6. 后端探测 ----------
say "6/6 后端探测"
"$PY" - "$MASKED_DIR" <<'EOF'
import sys
base = sys.argv[1]                    # .../vllm/vllm/masked
sys.path.insert(0, "/".join(base.split("/")[:-1]))  # masked 父目录（包上下文导入）
from masked.kernels import backends
print(f"  platform: {backends.detect_platform()}")
print(f"  backend:  {backends.backend_name()}")
print(f"  registry: {backends.available_backends()}")
EOF

# ---------- 汇总 ----------
say "汇总"
echo "  PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -eq 0 ] && [ "$PASS" -ge 2 ]; then
  echo "验证通过（Linux 密文内核环境就绪）"
  exit 0
else
  echo "存在失败项，请查上文输出"
  exit 1
fi
