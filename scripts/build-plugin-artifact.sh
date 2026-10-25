#!/usr/bin/env bash
# build-plugin-artifact.sh — GF.1.2 otpmask 插件出包（artifact 与源码版本绑定，评审 P0-2）
#
# 约束（研发计划 GF.1.2）：
#   1. 构建产物以 git tag（otpmask-plugin-vX.Y.Z）为 OCI tag，禁止手工出包冒充发布
#   2. 记录 源码 commit → artifact digest 映射（deploy/higress/artifact-map.csv）
#   3. 未打 tag 时仅允许 ALLOW_UNTAGGED=dev 显式出测试包（tag 记 dev）
#
# 用法：
#   scripts/build-plugin-artifact.sh                       # 要求当前 HEAD 有 otpmask-plugin-v* tag
#   ALLOW_UNTAGGED=dev scripts/build-plugin-artifact.sh    # 开发测试包（不入发布映射）
#   REGISTRY=registry.example.com/otpmask scripts/build-plugin-artifact.sh   # 构建+oras 推送
#
# 产物：gateway/wasm/otpmask-plugin/main.wasm（原地更新）+ 映射记录追加。
# CI 出包：本脚本即 CI 出包步骤；源码变更未同步推 artifact 视为发布事故（GF.1.2）。
set -euo pipefail

PLUGIN_DIR="gateway/wasm/otpmask-plugin"
WASM="$PLUGIN_DIR/main.wasm"
MAP="deploy/higress/artifact-map.csv"
TAG_PREFIX="otpmask-plugin-v"

cd "$(git rev-parse --show-toplevel)"

# 1. 版本绑定：tag 校验（评审 P0-2 的核心约束）
TAG="$(git tag --points-at HEAD | grep -E "^${TAG_PREFIX}" | head -1 || true)"
if [ -z "$TAG" ]; then
  if [ "${ALLOW_UNTAGGED:-}" = "dev" ]; then
    TAG="dev-$(git rev-parse --short HEAD)"
    echo "WARN: 未打 ${TAG_PREFIX}* tag，按 ALLOW_UNTAGGED=dev 出测试包（tag=$TAG，不入发布映射）" >&2
    UNRELEASED=1
  else
    echo "ERROR: 当前 commit 未打 ${TAG_PREFIX}X.Y.Z tag。" >&2
    echo "  发布出包须先: git tag ${TAG_PREFIX}X.Y.Z && git push --tags" >&2
    echo "  开发测试包: ALLOW_UNTAGGED=dev $0" >&2
    exit 1
  fi
else
  UNRELEASED=0
fi

COMMIT="$(git rev-parse HEAD)"
DIRTY="$(git status --porcelain -- "$PLUGIN_DIR" | wc -l | tr -d ' ')"
if [ "$DIRTY" != "0" ]; then
  echo "ERROR: $PLUGIN_DIR 存在未提交变更——先提交再出包（保证 commit→digest 映射可追溯）" >&2
  exit 1
fi

# 2. 构建（Go wasip1，现有构建链）
echo "== 构建 $WASM（$TAG @ ${COMMIT:0:12}） =="
GOOS=wasip1 GOARCH=wasm go build -trimpath -o "$WASM" "./$PLUGIN_DIR"

# 3. digest（sha256，与 OCI digest 同源口径）
if command -v sha256sum >/dev/null 2>&1; then
  DIGEST="sha256:$(sha256sum "$WASM" | awk '{print $1}')"
else
  DIGEST="sha256:$(shasum -a 256 "$WASM" | awk '{print $1}')"
fi
SIZE="$(wc -c < "$WASM" | tr -d ' ')"
echo "产物: $WASM ($SIZE bytes)"
echo "digest: $DIGEST"

# 4. 映射记录（源码 commit → artifact digest；发布包专用）
if [ "$UNRELEASED" = "0" ]; then
  if [ ! -f "$MAP" ]; then
    echo "git_commit,git_tag,artifact_digest,size_bytes,built_at" > "$MAP"
  fi
  BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "$COMMIT,$TAG,$DIGEST,$SIZE,$BUILT_AT" >> "$MAP"
  echo "映射记录已追加: $MAP"
else
  echo "测试包不入发布映射（$MAP）"
fi

# 5. 推送（可选；REGISTRY 提供时走 oras，按 Higress 插件 OCI 规范）
if [ -n "${REGISTRY:-}" ]; then
  command -v oras >/dev/null 2>&1 || { echo "ERROR: oras 未安装（oras.land）" >&2; exit 1; }
  IMAGE="$REGISTRY/otpmask-plugin:$TAG"
  echo "== oras push $IMAGE =="
  oras push "$IMAGE" \
    --artifact-type "application/vnd.higress.plugin.wasm" \
    "$WASM:application/vnd.wasm.content.layer.v1+wasm"
  echo "推送完成——请将 deploy/higress/otpmask-plugin.yaml 的 url 替换为该地址。"
else
  echo "提示：设置 REGISTRY=<registry> 可同时 oras push（当前仅本地出包）。"
fi

echo "== 完成：tag=$TAG digest=$DIGEST =="
