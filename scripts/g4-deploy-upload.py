import paramiko
import os
from pathlib import Path

HOST = "192.168.31.166"
USER = "root"
PASS = "yf0537"

LOCAL_REPO = Path(r"c:\Users\Robin\Desktop\方案\security-ai-gateway")
LOCAL_BIN = LOCAL_REPO / "tee-infer-service-linux"
LOCAL_POLICY = LOCAL_REPO / "gateway" / "tee-infer-service" / "policy"
LOCAL_SIDECAR = LOCAL_REPO / "scripts" / "qwen3guard-l2-sidecar.py"

REMOTE_BASE = "/opt/og16-g4"


def ssh_connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    return c


def run(c, cmd, timeout=120):
    print(f"$ {cmd}")
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if out.strip():
        print(out.rstrip())
    if err.strip() and "Warning" not in err and "warning" not in err:
        print("STDERR:", err.rstrip()[:500])
    rc = stdout.channel.recv_exit_status()
    print(f"  → exit {rc}\n")
    return rc, out, err


def sftp_upload(sftp, local_path, remote_path):
    size = os.path.getsize(local_path) / (1024 * 1024)
    print(f"  ↑ {local_path.name} ({size:.1f} MB) → {remote_path}")
    sftp.put(str(local_path), remote_path)


def main():
    c = ssh_connect()
    sftp = c.open_sftp()

    print("=== 创建目录 ===")
    run(c, f"mkdir -p {REMOTE_BASE}/bin {REMOTE_BASE}/policy {REMOTE_BASE}/sidecar {REMOTE_BASE}/gguf {REMOTE_BASE}/llama")

    print("=== 上传 tee-infer 二进制 ===")
    sftp_upload(sftp, LOCAL_BIN, f"{REMOTE_BASE}/bin/tee-infer-service")
    run(c, f"chmod +x {REMOTE_BASE}/bin/tee-infer-service")

    print("=== 上传 policy ===")
    for f in sorted(LOCAL_POLICY.glob("**/*")):
        if f.is_file():
            rel = f.relative_to(LOCAL_POLICY)
            remote = f"{REMOTE_BASE}/policy/{rel.as_posix()}"
            # 确保目录存在
            run(c, f"mkdir -p $(dirname {remote})")
            sftp_upload(sftp, f, remote)

    print("=== 上传侧车脚本 ===")
    sftp_upload(sftp, LOCAL_SIDECAR, f"{REMOTE_BASE}/sidecar/qwen3guard-l2-sidecar.py")
    run(c, f"chmod +x {REMOTE_BASE}/sidecar/qwen3guard-l2-sidecar.py")

    sftp.close()

    print("=== 校验 ===")
    run(c, f"ls -lh {REMOTE_BASE}/bin/tee-infer-service")
    run(c, f"find {REMOTE_BASE}/policy -type f | wc -l")
    run(c, f"ls -lh {REMOTE_BASE}/sidecar/")

    c.close()
    print("✅ 上传完成")


if __name__ == "__main__":
    main()
