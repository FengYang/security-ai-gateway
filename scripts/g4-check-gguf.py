import paramiko
import time

HOST = "192.168.31.166"
USER = "root"
PASS = "yf0537"


def run(c, cmd, timeout=60):
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    return rc, out, err


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)

    # 检查下载进度
    rc, out, _ = run(c, "ls -lh /opt/og16-g4/gguf/ 2>/dev/null")
    print("GGUF 目录:", out.strip())

    rc, out, _ = run(c, "ps aux | grep curl | grep -v grep | head -3")
    print("下载进程:", out.strip() or "(无)")

    rc, out, _ = run(c, "tail -3 /opt/og16-g4/gguf-download.log 2>/dev/null")
    print("下载日志末尾:", out.strip() or "(无)")

    c.close()


if __name__ == "__main__":
    main()
