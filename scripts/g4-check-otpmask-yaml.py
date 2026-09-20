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

    # otpmask wasmplugin 完整 YAML
    print("=== otpmask WasmPlugin 完整 YAML ===")
    rc, out, _ = run(c, "kubectl get wasmplugin otpmask -n higress-system -o yaml 2>&1")
    print(out[:4000])

    c.close()


if __name__ == "__main__":
    main()
