import paramiko

HOST = "192.168.31.166"
USER = "root"
PASS = "yf0537"


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

    # 检查二进制信息
    print("=== file 命令 ===")
    rc, out, _ = run(c, "file /opt/og16-g4/llama/llama-server")
    print(out)

    print("\n=== ldd ===")
    rc, out, _ = run(c, "cd /opt/og16-g4/llama && LD_LIBRARY_PATH=/opt/og16-g4/llama ldd ./llama-server")
    print(out)

    print("\n=== 直接运行版本 ===")
    rc, out, err = run(c, "cd /opt/og16-g4/llama && LD_LIBRARY_PATH=/opt/og16-g4/llama ./llama-server --version 2>&1")
    print("out:", repr(out[:200]))
    print("err:", repr(err[:200]))
    print("rc:", rc)

    print("\n=== strace 启动看错误 ===")
    rc, out, _ = run(c, "which strace || apt-get install -y -qq strace 2>&1 | tail -3", timeout=60)
    print(out[:300])
    rc, out, _ = run(c, "cd /opt/og16-g4/llama && LD_LIBRARY_PATH=/opt/og16-g4/llama strace -e trace=openat,execve ./llama-server --version 2>&1 | head -30", timeout=10)
    print(out[:1500])

    c.close()


if __name__ == "__main__":
    main()
