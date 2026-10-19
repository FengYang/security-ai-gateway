import os
import paramiko

HOST = "192.168.31.166"
USER = "root"
PASS = os.environ.get("SSH_PASSWORD")
if not PASS:
    raise SystemExit("[FATAL] 环境变量 SSH_PASSWORD 未设置（口令仅经环境变量注入，严禁硬编码/入库）")


def run(c, cmd, timeout=30):
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    return rc, out, err


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)

    # 检查 Python
    print("=== Python ===")
    rc, out, _ = run(c, "python3 --version 2>&1; pip3 --version 2>&1")
    print(out.strip())

    # 检查 GGUF 上传进度（看文件大小增长）
    print("\n=== GGUF 上传进度 ===")
    rc, out, _ = run(c, "ls -lh /opt/og16-g4/gguf/ 2>&1")
    print(out.strip())

    # 检查节点上有没有 python3 和必要的库
    print("\n=== Python 库检查 ===")
    rc, out, _ = run(c, "python3 -c 'import httpx; print(\"httpx ok\")' 2>&1")
    print(out.strip())
    rc, out, _ = run(c, "python3 -c 'import transformers; print(\"transformers ok\")' 2>&1")
    print(out.strip())

    c.close()


if __name__ == "__main__":
    main()
