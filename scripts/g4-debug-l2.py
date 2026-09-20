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

    # 从 pod 里测侧车连通性
    print("=== 从 tee-infer pod 测侧车连通性 ===")
    # 用 wget（alpine 没有 curl）
    rc, out, _ = run(c, f"kubectl exec -n otpmask {pod} -- wget -qO- http://qwen3guard-l2:19112/healthz 2>&1")
    print(f"healthz: {out.strip()}")

    rc, out, _ = run(c, f"kubectl exec -n otpmask {pod} -- wget --post-data='{{\"text\":\"hi\"}}' --header='Content-Type: application/json' -qO- http://qwen3guard-l2:19112/classify 2>&1")
    print(f"\nclassify: {out.strip()[:500]}")

    # DNS 解析
    print("\n=== DNS 解析 ===")
    rc, out, _ = run(c, f"kubectl exec -n otpmask {pod} -- nslookup qwen3guard-l2 2>&1 || kubectl exec -n otpmask {pod} -- getent hosts qwen3guard-l2 2>&1")
    print(out[:300])

    # 可信域检查
    print("\n=== 可信域白名单 ===")
    # 看启动日志里的可信域
    rc, out, _ = run(c, f"kubectl logs -n otpmask {pod} 2>&1 | grep -i '可信域\\|allowed'")
    print(out)

    # Endpoints 是否正确
    print("\n=== Endpoints ===")
    rc, out, _ = run(c, "kubectl get endpoints qwen3guard-l2 -n otpmask -o wide")
    print(out)

    c.close()


if __name__ == "__main__":
    main()
