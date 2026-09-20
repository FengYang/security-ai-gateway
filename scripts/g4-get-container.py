import paramiko
import time
import json

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

    # 先看当前 deployment 的完整 container spec
    print("=== 获取当前 container spec ===")
    rc, out, _ = run(c, "kubectl get deploy -n otpmask tee-infer-service -o jsonpath='{.spec.template.spec.containers[0]}' | python3 -m json.tool 2>&1 | head -50")
    print(out[:2000])

    c.close()


if __name__ == "__main__":
    main()
