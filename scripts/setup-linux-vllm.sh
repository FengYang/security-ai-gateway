#!/usr/bin/env bash
# setup-linux-vllm.sh - 在独立 Linux 主机上部署 vLLM CPU 版（含全部踩坑修复）
#
# 用法（root 或 sudo）：
#   bash setup-linux-vllm.sh <vllm源码路径> [模型名]
#   例：bash setup-linux-vllm.sh /opt/vllm Qwen/Qwen2.5-0.5B-Instruct
#
# 说明：vllm 源码需先放到主机（git clone 或从本项目拷贝）。
set -e

SRC=${1:?用法: setup-linux-vllm.sh <vllm源码路径> [模型名]}
MODEL=${2:-Qwen/Qwen2.5-0.5B-Instruct}
VENV=/opt/venv-vllm
PY=$VENV/bin/python
PIP=$VENV/bin/pip
LOG=/opt/vllm-build.log
MIRROR=https://pypi.tuna.tsinghua.edu.cn/simple

echo "== [1/5] 系统依赖 =="
if [ "$(id -u)" -ne 0 ]; then echo "请用 root 或 sudo 执行"; exit 1; fi
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  build-essential cmake ninja-build python3-dev python3-venv \
  libopenblas-dev libgomp1 libaio-dev pkg-config git curl

echo "== [2/5] venv + torch CPU =="
python3 -m venv "$VENV"
"$PIP" install -q -U pip -i "$MIRROR"
"$PIP" install -q torch==2.13.0 --index-url https://download.pytorch.org/whl/cpu
"$PY" -c "import torch, torch.nn as nn; print('torch', torch.__version__)"

echo "== [3/5] 编译安装 vLLM CPU（20-40 分钟）=="
"$PIP" install -q setuptools wheel setuptools-scm setuptools-rust -i "$MIRROR"
cd "$SRC"
git config --global --add safe.directory '*' 2>/dev/null || true
# 跳过 git describe（源码不含完整 git 历史时）
export SETUPTOOLS_SCM_PRETEND_VERSION=0.22.1
VLLM_TARGET_DEVICE=cpu "$PIP" install -e . --no-build-isolation -i "$MIRROR" \
  2>&1 | tee "$LOG" | tail -5

echo "== [4/5] 验证 import =="
"$PY" -c "import vllm; print('vllm', vllm.__version__)"

echo "== [5/5] 下载模型并启动 CPU serve =="
"$PIP" install -q huggingface_hub -i "$MIRROR"
"$PY" -c "
from huggingface_hub import snapshot_download
p = snapshot_download('$MODEL')
print('model at', p)
" || echo "HF 下载失败，可改用 ModelScope: pip install modelscope && modelscope download --model Qwen/Qwen2.5-0.5B-Instruct"

echo "== 启动命令 =="
echo "nohup $PY -m vllm.entrypoints.openai.api_server --model $MODEL --device cpu --port 8000 &"
echo "== 完成。测试: curl http://localhost:8000/v1/models =="
