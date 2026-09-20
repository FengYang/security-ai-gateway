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

    pod = "tee-infer-service-cbb9ddc5f-tpxng"

    # 详细看 L2 调用：wget -S 看响应头
    print("=== wget -S classify ===")
    rc, out, _ = run(c, f"""
    kubectl exec -n otpmask {pod} -- wget -S --post-data='{{\"text\":\"hello\"}}' \
      --header='Content-Type: application/json' \
      http://qwen3guard-l2.otpmask:19112/classify 2>&1 | head -30
    """)
    print(out[:1500])

    # 再看一下日志里有没有 L2 调用的详细错误
    print("\n=== tee-infer 日志（详细） ===")
    rc, out, _ = run(c, f"kubectl logs -n otpmask {pod} 2>&1 | tail -100")
    print(out[-3000:])

    c.close()


if __name__ == "__main__":
    main()
