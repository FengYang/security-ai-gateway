#!/usr/bin/env python3
"""
部署脚本：把本地 tee-infer 二进制 + policy 传到 K3S 节点，构建 OCI 镜像并导入 containerd。
同时部署 llama-server + 侧车到 K3S。
"""
import paramiko
import os
import sys
import time
from pathlib import Path

HOST = "192.168.31.166"
USER = "root"
PASS = "yf0537"

LOCAL_REPO = Path(r"c:\Users\Robin\Desktop\方案\security-ai-gateway")
LOCAL_BIN = LOCAL_REPO / "tee-infer-service-linux"
LOCAL_POLICY = LOCAL_REPO / "gateway" / "tee-infer-service" / "policy"
LOCAL_SIDECAR = LOCAL_REPO / "scripts" / "qwen3guard-l2-sidecar.py"

REMOTE_DIR = "/opt/og16-g4"


def ssh_connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    return c


def run(c, cmd, timeout=60):
    print(f"$ {cmd}")
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if out.strip():
        print(out.rstrip())
    if err.strip():
        print("STDERR:", err.rstrip()[:500])
    rc = stdout.channel.recv_exit_status()
    print(f"  → exit {rc}\n")
    return rc, out, err


def sftp_upload(c, local_path, remote_path):
    sftp = c.open_sftp()
    print(f"  upload {local_path} → {remote_path}")
    sftp.put(str(local_path), remote_path)
    sftp.close()


def main():
    c = ssh_connect()
    print("=== 1. 创建目录 ===")
    run(c, f"mkdir -p {REMOTE_DIR}/policy {REMOTE_DIR}/build {REMOTE_DIR}/gguf")

    print("=== 2. 上传 tee-infer 二进制 ===")
    sftp_upload(c, LOCAL_BIN, f"{REMOTE_DIR}/build/tee-infer-service")
    run(c, f"chmod +x {REMOTE_DIR}/build/tee-infer-service")

    print("=== 3. 上传 policy 目录 ===")
    sftp = c.open_sftp()
    for f in LOCAL_POLICY.glob("*.json"):
        remote = f"{REMOTE_DIR}/build/policy/{f.name}"
        print(f"  upload policy/{f.name}")
        sftp.put(str(f), remote)
    sftp.close()

    print("=== 4. 上传侧车脚本 ===")
    sftp_upload(c, LOCAL_SIDECAR, f"{REMOTE_DIR}/qwen3guard-l2-sidecar.py")

    # 检查大小
    run(c, f"ls -lh {REMOTE_DIR}/build/tee-infer-service")
    run(c, f"ls {REMOTE_DIR}/build/policy/ | wc -l")

    print("=== 5. 写 Dockerfile 并构建镜像 ===")
    dockerfile = """FROM alpine:3.20
COPY tee-infer-service /usr/local/bin/tee-infer-service
COPY policy /app/policy
RUN apk add --no-cache ca-certificates
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/tee-infer-service"]
"""
    sftp = c.open_sftp()
    with sftp.file(f"{REMOTE_DIR}/build/Dockerfile", "w") as f:
        f.write(dockerfile)
    sftp.close()

    # 用 k3s ctr 构建？不行，ctr 不能 build。用 buildah 也没有。
    # 换个方式：直接把二进制 + 依赖打进容器 —— 用 ctr + 导入基础镜像的方式太复杂
    # 最简单：节点上如果有 buildah 就用 buildah，没有就用 skopeo？
    # 实际上，k3s 有 containerd，可以用 nerdctl，但没装。
    # 方案：把二进制和 policy 放到 hostPath，然后改 deployment 直接用 hostPath 挂载替换——
    # 不行，因为 deployment 用的是镜像。
    #
    # 更好的方案：用 ctr 导入一个新镜像。我们可以做一个最小的 OCI 镜像。
    # 但太复杂了。最简单的办法：
    # 1. 拿现有镜像 otpmask/tee-infer-service:og11 当基础
    # 2. 用 kubectl set image 前，先做一个 init container 把二进制替换掉？
    # 不行，readOnlyRootFilesystem。
    #
    # 最佳方案：用 docker 在本地构建（先启动 Docker Desktop），然后 save 成 tar 传上去 import。
    # 但用户可能不想启动 Docker。
    #
    # 再想：我们能不能直接在节点上跑二进制（不用容器），然后用 kubectl port-forward？
    # 不行，因为要验证 Higress → tee-infer 全链路，必须走 Higress Ingress。
    #
    # 折中方案：改 deployment 为一个运行 hostPath 上二进制的容器
    # 用 alpine 镜像 + hostPath 挂载，command 直接跑 hostPath 上的二进制
    # 这样就不用构建新镜像了。

    print("=== 6. 用 alpine + hostPath 方案替代构建新镜像 ===")
    # 先看 alpine 镜像在不在
    rc, out, _ = run(c, "k3s ctr images ls | grep alpine | head -3")
    if "alpine" not in out:
        print("拉取 alpine:3.20 ...")
        run(c, "k3s ctr images pull docker.io/library/alpine:3.20", timeout=120)

    c.close()
    print("\n✅ 上传完成")


if __name__ == "__main__":
    main()
