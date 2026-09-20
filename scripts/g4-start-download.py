import paramiko
from pathlib import Path
import time

HOST = "192.168.31.166"
USER = "root"
PASS = "yf0537"

LOCAL_SCRIPT = Path(r"c:\Users\Robin\Desktop\方案\security-ai-gateway\scripts\g4-download.sh")


def ssh_connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    return c


def run(c, cmd, timeout=120):
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    return rc, out, err


def main():
    c = ssh_connect()
    sftp = c.open_sftp()

    # 上传下载脚本
    sftp.put(str(LOCAL_SCRIPT), "/opt/og16-g4/download.sh")
    run(c, "chmod +x /opt/og16-g4/download.sh")

    # 检查是否已经下载完了
    rc, out, _ = run(c, "ls -lh /opt/og16-g4/gguf/*.gguf 2>/dev/null; ls -lh /opt/og16-g4/llama/llama-server 2>/dev/null")
    if "Q8_0" in out and "llama-server" in out:
        print("✅ llama-server + GGUF 都已存在，跳过下载")
        print(out)
        c.close()
        return

    # 后台启动下载
    print("🚀 启动后台下载（llama-server + GGUF，总共约 870MB）...")
    run(c, "nohup /opt/og16-g4/download.sh > /opt/og16-g4/download.out 2>&1 &")
    time.sleep(2)

    # 检查是否在运行
    rc, out, _ = run(c, "ps aux | grep download.sh | grep -v grep | head -3")
    print(f"下载进程: {out.strip()}")

    sftp.close()
    c.close()
    print("\n⏳ 下载已在后台启动，稍后检查进度（tail /opt/og16-g4/download.log）")


if __name__ == "__main__":
    main()
