import os
import paramiko
import time

HOST = "192.168.31.166"
USER = "root"
PASS = os.environ.get("SSH_PASSWORD")
if not PASS:
    raise SystemExit("[FATAL] 环境变量 SSH_PASSWORD 未设置（口令仅经环境变量注入，严禁硬编码/入库）")


def ssh_connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    return c


def run(c, cmd, timeout=60):
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    return rc, out, err


def main():
    c = ssh_connect()

    # 检查进程
    rc, out, _ = run(c, "ps aux | grep -E 'download|curl' | grep -v grep | head -5")
    print("运行中的下载进程:")
    print(out or "  (无)")

    # 检查日志最后 10 行
    rc, out, _ = run(c, "tail -20 /opt/og16-g4/download.log 2>/dev/null")
    print("\n下载日志最后 20 行:")
    print(out or "  (暂无日志)")

    # 检查文件大小
    rc, out, _ = run(c, "ls -lh /opt/og16-g4/llama/ 2>/dev/null; echo '---'; ls -lh /opt/og16-g4/gguf/ 2>/dev/null")
    print("\n文件列表:")
    print(out or "  (无)")

    c.close()


if __name__ == "__main__":
    main()
