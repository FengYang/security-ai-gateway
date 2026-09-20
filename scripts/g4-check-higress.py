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

    # higress-gateway service
    print("=== higress-gateway svc ===")
    rc, out, _ = run(c, "kubectl get svc higress-gateway -n higress-system -o wide")
    print(out)

    # svclb-higress-gateway (DaemonSet)
    print("=== svclb ===")
    rc, out, _ = run(c, "kubectl get svc -A | grep higress-gateway")
    print(out)

    # 节点上的监听端口
    print("=== 节点端口 ===")
    rc, out, _ = run(c, "ss -tlnp | grep -E '80|443|8080' | head -10")
    print(out)

    # 测一下节点 IP:80 能不能访问
    print("=== 本地 80 端口测试 ===")
    rc, out, _ = run(c, "curl -s -I http://127.0.0.1:80/ 2>&1 | head -5")
    print(out)

    # otpmask 插件的配置（怎么传明文？怎么调用？）
    print("=== otpmask wasm plugin 配置 ===")
    rc, out, _ = run(c, "kubectl get wasmplugin otpmask -n higress-system -o json 2>&1 | python3 -c \"import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get('spec',{}), indent=2, ensure_ascii=False))\" 2>&1 | head -60")
    print(out)

    c.close()


if __name__ == "__main__":
    main()
