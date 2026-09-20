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

    # 列出所有 tee-infer pod
    print("=== tee-infer pods ===")
    rc, out, _ = run(c, "kubectl get pods -n otpmask | grep tee-infer")
    print(out)

    # 拿新 pod 名
    pod_name = out.strip().split('\n')[-1].split()[0]
    print(f"新 pod: {pod_name}")

    # describe 看事件
    print("\n=== describe ===")
    rc, out, _ = run(c, f"kubectl describe pod -n otpmask {pod_name} 2>&1 | tail -40")
    print(out)

    # 日志
    print("\n=== logs ===")
    rc, out, err = run(c, f"kubectl logs -n otpmask {pod_name} 2>&1 | tail -50")
    print(out)
    if err.strip():
        print("STDERR:", err[:500])

    c.close()


if __name__ == "__main__":
    main()
