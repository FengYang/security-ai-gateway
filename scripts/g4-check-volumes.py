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

    print("=== 检查 volumes 和 volumeMounts ===")
    rc, out, _ = run(c, "kubectl get deploy -n otpmask tee-infer-service -o jsonpath='{.spec.template.spec.volumes}' | python3 -m json.tool 2>&1")
    print("Volumes:")
    print(out)

    rc, out, _ = run(c, "kubectl get deploy -n otpmask tee-infer-service -o jsonpath='{.spec.template.spec.containers[0].volumeMounts}' | python3 -m json.tool 2>&1")
    print("\nVolumeMounts:")
    print(out)

    # 和备份对比
    print("\n=== 备份文件中的 volumes ===")
    rc, out, _ = run(c, "cat /opt/og16-g4/tee-infer-backup.yaml | grep -A 20 'volumes:' | head -25")
    print(out)

    c.close()


if __name__ == "__main__":
    main()
