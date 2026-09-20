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

    # 看 tee-infer 的启动参数
    print("=== tee-infer 启动参数 ===")
    rc, out, _ = run(c, "kubectl get deploy -n otpmask tee-infer-service -o jsonpath='{.spec.template.spec.containers[0].args}' | python3 -m json.tool 2>&1")
    print(out)

    # 也看环境变量
    print("\n=== tee-infer 环境变量（output-guard 相关）===")
    rc, out, _ = run(c, "kubectl get deploy -n otpmask tee-infer-service -o jsonpath='{.spec.template.spec.containers[0].env}' | python3 -m json.tool 2>&1")
    print(out[:3000])

    c.close()


if __name__ == "__main__":
    main()
