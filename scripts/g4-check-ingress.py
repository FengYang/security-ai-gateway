import os
import paramiko

HOST = "192.168.31.166"
USER = "root"
PASS = os.environ.get("SSH_PASSWORD")
if not PASS:
    raise SystemExit("[FATAL] 环境变量 SSH_PASSWORD 未设置（口令仅经环境变量注入，严禁硬编码/入库）")


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

    # ingress 详情
    print("=== ingress infer 详情 ===")
    rc, out, _ = run(c, "kubectl get ingress infer -n higress-system -o yaml 2>&1")
    print(out[:4000])

    # 也看看 MCPBridge 或其他 Higress CRD
    print("\n=== 所有 wasmplugin ===")
    rc, out, _ = run(c, "kubectl get wasmplugins -A 2>&1")
    print(out)

    c.close()


if __name__ == "__main__":
    main()
