#!/bin/bash
# 在节点上后台下载 llama-server + GGUF
set -e

BASE=/opt/og16-g4
mkdir -p $BASE/llama $BASE/gguf

LOG=$BASE/download.log
echo "=== 开始下载: $(date) ===" > $LOG

# 1. llama-server CPU 版
if [ ! -f $BASE/llama/llama-server ]; then
    echo "下载 llama-server..." >> $LOG
    cd $BASE/llama
    # b4930 是较新的 stable
    curl -L --fail -o llama-cpu.zip \
      "https://github.com/ggerganov/llama.cpp/releases/download/b4930/llama-b4930-bin-ubuntu-x64.zip" \
      >> $LOG 2>&1
    unzip -o llama-cpu.zip >> $LOG 2>&1
    chmod +x llama-server
    echo "llama-server 就绪: $(ls -lh llama-server | awk '{print $5}')" >> $LOG
else
    echo "llama-server 已存在" >> $LOG
fi

# 2. Qwen3Guard Q8_0 GGUF
if [ ! -f $BASE/gguf/Qwen3Guard-Gen-0.6B.Q8_0.gguf ]; then
    echo "下载 Qwen3Guard Q8_0 GGUF..." >> $LOG
    cd $BASE/gguf
    # 用 hf-mirror 加速
    curl -L --fail -o Qwen3Guard-Gen-0.6B.Q8_0.gguf \
      "https://hf-mirror.com/Qwen/Qwen3Guard-Gen-0.6B-GGUF/resolve/main/Qwen3Guard-Gen-0.6B.Q8_0.gguf" \
      >> $LOG 2>&1
    echo "GGUF 就绪: $(ls -lh Qwen3Guard-Gen-0.6B.Q8_0.gguf | awk '{print $5}')" >> $LOG
else
    echo "GGUF 已存在" >> $LOG
fi

echo "=== 下载完成: $(date) ===" >> $LOG
echo "DONE" >> $LOG
