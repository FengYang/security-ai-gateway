#!/usr/bin/env bash
# 路线2 Linux 产物构建（二进制 + 可选加速 .so）。默认纯 CPU（CGO=0）。
# 用法：
#   bash packaging/route2/build.sh              # 构建 tee-infer-service + route2-client
#   WITH_ACCEL=1 bash packaging/route2/build.sh # 另编 libaccel_ascend.so（可移植参考实现）
set -euo pipefail
cd "$(dirname "$0")/../.." # 回到仓库根
OUT="${OUT:-dist}"
mkdir -p "$OUT"

export GOFLAGS=-mod=mod
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"

echo "==> 构建 tee-infer-service (linux/amd64, CGO=0)"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
  -o "$OUT/tee-infer-service" ./gateway/tee-infer-service

echo "==> 构建 route2-client (linux/amd64, CGO=0)"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
  -o "$OUT/route2-client" ./cmd/route2-client

if [ "${WITH_ACCEL:-0}" = "1" ]; then
  echo "==> 构建昇腾可移植参考 .so（libaccel_ascend.so，任意 x86_64/aarch64 可编）"
  g++ -shared -fPIC ../masked-infer/core/cipher_linear_int128_ascend.cpp \
    -o "$OUT/libaccel_ascend.so"
  echo "    CUDA 后端需 nvcc：见 ../masked-infer/core/accel_linear_int128.h 头注释"
fi

echo "==> 产物："
ls -la "$OUT"
