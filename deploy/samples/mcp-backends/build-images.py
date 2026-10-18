#!/usr/bin/env python3
"""P2-1 T-2：样例 MCP 后端离线镜像构建器（纯 Python；无需 Docker）。

产出（OCI image layout，含 io.containerd.image.name 注解）：
  dist/mcp-demo-0.1.0.tar   → docker.io/otpmask/mcp-demo:0.1.0
  dist/mcp-fs-0.1.0.tar     → docker.io/otpmask/mcp-fs:0.1.0

用法（仓库根目录）：
  python deploy/samples/mcp-backends/build-images.py                # 构建两个
  python deploy/samples/mcp-backends/build-images.py --src demo     # 只构建一个

节点离线导入：
  scp dist/mcp-demo-0.1.0.tar <node>:/tmp/
  k3s ctr -n k8s.io images import /tmp/mcp-demo-0.1.0.tar

设计口径：与 cryptopsvc 离线导入先例同法（Windows 交叉编译静态 ELF → 手工 OCI
layout → ctr import）；本脚本把该过程固化、可复现（固定 mtime，重复构建同摘要）。
样例件，不进入产品发布物。
"""
import argparse
import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
IMAGE_PREFIX = "otpmask"
TAG = "0.1.0"
EPOCH = 1_700_000_000  # 固定 mtime，产出可复现
CREATED = "2023-11-14T22:13:20Z"

SAMPLES = {
    "demo": {
        "pkg": "./deploy/samples/mcp-backends/demo",
        "env": ["LISTEN=:8080"],
    },
    "filesystem": {
        "pkg": "./deploy/samples/mcp-backends/filesystem",
        "env": ["LISTEN=:8080", "FS_ROOT=/data"],
    },
}

MT_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MT_CONFIG = "application/vnd.oci.image.config.v1+json"
MT_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
MT_INDEX = "application/vnd.oci.image.index.v1+json"


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_binary(src: str) -> bytes:
    """Windows 主机上交叉编译 linux/amd64 静态二进制。"""
    env = dict(os.environ, GOOS="linux", GOARCH="amd64", CGO_ENABLED="0")
    with tempfile.TemporaryDirectory(prefix="mcp-sample-build-") as td:
        out = os.path.join(td, "app")
        cmd = [
            "go", "build", "-trimpath", "-ldflags", "-s -w", "-o", out,
            SAMPLES[src]["pkg"],
        ]
        print(f"-- 构建 {src}: {' '.join(cmd)}（cwd={ROOT}）")
        subprocess.run(cmd, cwd=ROOT, env=env, check=True)
        with open(out, "rb") as f:
            return f.read()


def make_layer(app: bytes) -> tuple[bytes, str]:
    """打包单层 tar.gz（/bin/app，0755）；返回 (blob, 未压缩层 diff_id)。"""
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        info = tarfile.TarInfo("bin/app")
        info.mode = 0o755
        info.uid = 0
        info.gid = 0
        info.mtime = EPOCH
        info.size = len(app)
        tf.addfile(info, io.BytesIO(app))
    tar_bytes = tar_buf.getvalue()
    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb", mtime=0) as gz:
        gz.write(tar_bytes)
    return gz_buf.getvalue(), sha256(tar_bytes)


def make_config(diff_id: str, env: list[str]) -> bytes:
    cfg = {
        "created": CREATED,
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "Entrypoint": ["/bin/app"],
            "Env": env,
            "ExposedPorts": {"8080/tcp": {}},
            "User": "65532:65532",
            "WorkingDir": "/",
        },
        "rootfs": {"type": "layers", "diff_ids": [diff_id]},
        "history": [{"created": CREATED, "created_by": "build-images.py (P2-1 T-2)"}],
    }
    return json.dumps(cfg, ensure_ascii=False, indent=2).encode()


def pack_oci(src: str, out_tar: str) -> dict:
    """构建单个样例的 OCI layout tar；返回自检摘要。"""
    name = f"docker.io/{IMAGE_PREFIX}/mcp-{'fs' if src == 'filesystem' else src}:{TAG}"
    app = build_binary(src)
    layer_blob, diff_id = make_layer(app)
    config_blob = make_config(diff_id, SAMPLES[src]["env"])

    blobs = {
        sha256(config_blob): config_blob,
        sha256(layer_blob): layer_blob,
    }
    manifest = {
        "schemaVersion": 2,
        "mediaType": MT_MANIFEST,
        "config": {
            "mediaType": MT_CONFIG,
            "digest": sha256(config_blob),
            "size": len(config_blob),
        },
        "layers": [
            {
                "mediaType": MT_LAYER,
                "digest": sha256(layer_blob),
                "size": len(layer_blob),
            }
        ],
    }
    manifest_blob = json.dumps(manifest, ensure_ascii=False, indent=2).encode()
    blobs[sha256(manifest_blob)] = manifest_blob

    index = {
        "schemaVersion": 2,
        "mediaType": MT_INDEX,
        "manifests": [
            {
                "mediaType": MT_MANIFEST,
                "digest": sha256(manifest_blob),
                "size": len(manifest_blob),
                "platform": {"architecture": "amd64", "os": "linux"},
                "annotations": {
                    "io.containerd.image.name": name,
                    "org.opencontainers.image.ref.name": TAG,
                },
            }
        ],
    }
    index_blob = json.dumps(index, ensure_ascii=False, indent=2).encode()

    os.makedirs(os.path.dirname(out_tar), exist_ok=True)
    with tarfile.open(out_tar, mode="w") as tf:
        def add(path: str, data: bytes) -> None:
            info = tarfile.TarInfo(path)
            info.mode = 0o644
            info.mtime = EPOCH
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        add("oci-layout", b'{"imageLayoutVersion": "1.0.0"}')
        add("index.json", index_blob)
        for digest, blob in blobs.items():
            add(f"blobs/sha256/{digest.split(':', 1)[1]}", blob)

    return {
        "image": name,
        "tar": out_tar,
        "tar_size": os.path.getsize(out_tar),
        "layer_size": len(layer_blob),
        "config_digest": sha256(config_blob),
        "manifest_digest": sha256(manifest_blob),
    }


def self_check(out_tar: str) -> None:
    """重开 tar 自检：blobs 文件名与其内容 sha256 一致。"""
    with tarfile.open(out_tar, mode="r") as tf:
        names = tf.getnames()
        for n in names:
            if not n.startswith("blobs/sha256/"):
                continue
            want = n.rsplit("/", 1)[1]
            got = hashlib.sha256(tf.extractfile(n).read()).hexdigest()
            if want != got:
                raise SystemExit(f"自检失败：{n} 内容 sha256={got}")
        for need in ("oci-layout", "index.json"):
            if need not in names:
                raise SystemExit(f"自检失败：缺 {need}")
    print(f"   自检 OK：{os.path.basename(out_tar)}（oci-layout/index.json/blobs 摘要一致）")


def main() -> None:
    ap = argparse.ArgumentParser(description="P2-1 T-2 样例 MCP 后端离线镜像构建器")
    ap.add_argument("--src", choices=sorted(SAMPLES), action="append",
                    help="只构建指定样例（可重复；缺省两个全建）")
    ap.add_argument("--outdir", default=os.path.join(ROOT, "dist"),
                    help="输出目录（缺省 <repo>/dist）")
    args = ap.parse_args()

    targets = args.src or sorted(SAMPLES)
    results = []
    for src in targets:
        fname = f"mcp-{'fs' if src == 'filesystem' else src}-{TAG}.tar"
        out_tar = os.path.join(args.outdir, fname)
        print(f"== 构建样例镜像：{src}")
        r = pack_oci(src, out_tar)
        self_check(out_tar)
        results.append(r)

    print("\n== 汇总（三要素：命令 / 结果 / 落盘）")
    for r in results:
        print(f"   {r['image']}")
        print(f"     层 {r['layer_size']} B；tar {r['tar_size']} B → {r['tar']}")
        print(f"     manifest {r['manifest_digest']}")
    print("\n节点离线导入（示例）：")
    for r in results:
        print(f"   scp \"{r['tar']}\" <node>:/tmp/ && "
              f"k3s ctr -n k8s.io images import /tmp/{os.path.basename(r['tar'])}")


if __name__ == "__main__":
    sys.exit(main())
