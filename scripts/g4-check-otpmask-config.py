import paramiko
import json

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

    # otpmask 插件完整配置
    print("=== otpmask WasmPlugin 配置 ===")
    rc, out, _ = run(c, "kubectl get wasmplugin otpmask -n higress-system -o jsonpath='{.spec.defaultConfig}' 2>&1 | python3 -m json.tool")
    print(out[:3000])

    # 也看一下 infer ingress
    print("\n=== infer ingress ===")
    rc, out, _ = run(c, "kubectl get ingress -A | grep -i infer")
    print(out)

    # 看看 tee-infer service 在哪里
    print("\n=== tee-infer service ===")
    rc, out, _ = run(c, "kubectl get svc -A | grep tee-infer")
    print(out)

    c.close()


if __name__ == "__main__":
    main()
