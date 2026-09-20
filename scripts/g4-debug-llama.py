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

    # 直接前台跑一下看错误
    print("=== 前台测试 llama-server ===")
    rc, out, err = run(c, "cd /opt/og16-g4/llama && LD_LIBRARY_PATH=/opt/og16-g4/llama ./llama-server --help 2>&1 | head -10", timeout=10)
    print("out:", out[:500])
    print("err:", err[:500])
    print("rc:", rc)

    # 如果 help 能出来，说明库没问题，是启动参数问题
    if rc == 0:
        print("\n✅ 库没问题，试启动看看...")
        # 用 bash -c 确保 env 传对
        run(c, """
        cat > /opt/og16-g4/start-llama.sh << 'EOF'
#!/bin/bash
export LD_LIBRARY_PATH=/opt/og16-g4/llama
cd /opt/og16-g4/llama
exec ./llama-server \
  -m /opt/og16-g4/gguf/Qwen3Guard-Gen-0.6B.Q8_0.gguf \
  --port 19110 --host 0.0.0.0 \
  -np 2 -c 2048
EOF
        chmod +x /opt/og16-g4/start-llama.sh
        """)
        # 后台启动
        run(c, "nohup /opt/og16-g4/start-llama.sh > /opt/og16-g4/llama-server.log 2>&1 & echo PID=$!")
        import time
        time.sleep(5)
        rc, out, _ = run(c, "ps aux | grep llama-server | grep -v grep")
        print("进程:", out[:500])
        rc, out, _ = run(c, "head -30 /opt/og16-g4/llama-server.log")
        print("日志头:", out[:1000])

    c.close()


if __name__ == "__main__":
    main()
