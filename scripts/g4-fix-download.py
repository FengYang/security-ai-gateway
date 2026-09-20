import paramiko
import time

HOST = "192.168.31.166"
USER = "root"
PASS = "yf0537"


def run(c, cmd, timeout=120):
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    return rc, out, err


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)

    # 移动 llama-server 到正确位置
    print("=== 检查 llama-server ===")
    rc, out, _ = run(c, "find /opt/og16-g4/llama -name 'llama-server' -type f 2>/dev/null")
    print(out)

    # 把二进制移出来
    rc, out, _ = run(c, "cp /opt/og16-g4/llama/build/bin/llama-server /opt/og16-g4/llama/llama-server 2>&1 && chmod +x /opt/og16-g4/llama/llama-server && ls -lh /opt/og16-g4/llama/llama-server")
    print(out)

    # 看看脚本为什么 GGUF 没下
    print("\n=== 完整下载日志 ===")
    rc, out, _ = run(c, "cat /opt/og16-g4/download.log 2>/dev/null; echo '---'; cat /opt/og16-g4/download.out 2>/dev/null | tail -30")
    print(out[-2000:])

    # 直接手动下载 GGUF（后台）
    print("\n=== 手动启动 GGUF 下载 ===")
    rc, out, _ = run(c, """
    cd /opt/og16-g4/gguf
    nohup curl -L -o Qwen3Guard-Gen-0.6B.Q8_0.gguf \
      "https://hf-mirror.com/Qwen/Qwen3Guard-Gen-0.6B-GGUF/resolve/main/Qwen3Guard-Gen-0.6B.Q8_0.gguf" \
      > /opt/og16-g4/gguf-download.log 2>&1 &
    echo "PID: $!"
    """)
    print(out)

    c.close()


if __name__ == "__main__":
    main()
