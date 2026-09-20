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

    # 看看 build/bin 里有什么 .so
    print("=== build/bin 共享库 ===")
    rc, out, _ = run(c, "ls -lh /opt/og16-g4/llama/build/bin/*.so* 2>&1")
    print(out)

    # 全部复制到 llama 目录
    print("\n=== 复制所有 .so ===")
    run(c, "cp /opt/og16-g4/llama/build/bin/*.so* /opt/og16-g4/llama/ 2>&1")
    rc, out, _ = run(c, "ls -lh /opt/og16-g4/llama/*.so*")
    print(out)

    # 再启动
    print("\n=== 启动 llama-server ===")
    run(c, "pkill -9 llama-server 2>/dev/null; sleep 1")
    run(c, """
    cd /opt/og16-g4/llama &&
    LD_LIBRARY_PATH=/opt/og16-g4/llama
    nohup ./llama-server \
      -m /opt/og16-g4/gguf/Qwen3Guard-Gen-0.6B.Q8_0.gguf \
      --port 19110 --host 0.0.0.0 \
      -np 2 -c 2048 \
      > /opt/og16-g4/llama-server.log 2>&1 &
    """)
    time.sleep(3)

    rc, out, _ = run(c, "ps aux | grep llama-server | grep -v grep | head -3")
    print("进程:", out.strip() or "(未找到)")

    # 等健康
    print("等待加载...")
    for i in range(50):
        time.sleep(2)
        rc, out, _ = run(c, "curl -s http://127.0.0.1:19110/health 2>&1")
        if rc == 0 and "status" in out.lower():
            print(f"  ✅ llama-server 就绪（第 {(i+1)*2}s）: {out.strip()[:100]}")
            break
        if i % 5 == 4:
            rc, log, _ = run(c, "tail -3 /opt/og16-g4/llama-server.log")
            print(f"  ...({(i+1)*2}s) 日志: {log.strip()[-100:]}")
    else:
        print("  ❌ 未就绪")
        rc, out, _ = run(c, "tail -20 /opt/og16-g4/llama-server.log")
        print(out[-1500:])

    c.close()


if __name__ == "__main__":
    main()
