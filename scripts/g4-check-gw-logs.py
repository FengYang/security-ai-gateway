import os
import paramiko
import time

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

    pod = "tee-infer-service-75c5b5fcbb-54cds"
    gw_pod = "higress-gateway-dc6665557-trptz"

    # 看 tee-infer 完整启动日志
    print("=== tee-infer 完整启动日志 ===")
    rc, out, _ = run(c, f"kubectl logs -n otpmask {pod} 2>&1")
    print(out[-2000:])

    # 看 Higress 网关日志里的 otpmask 错误
    print("\n=== Higress 网关最新日志（otpmask 相关）===")
    rc, out, _ = run(c, f"kubectl logs -n higress-system {gw_pod} --tail=100 2>&1 | grep -iE 'otpmask|error|unavail' | tail -20")
    print(out[-1500:] if out.strip() else "(无)")

    # 再看 Higress 全部日志最后 30 行
    print("\n=== Higress 网关最新日志（最后 30 行）===")
    rc, out, _ = run(c, f"kubectl logs -n higress-system {gw_pod} --tail=30 2>&1")
    print(out[-1500:])

    c.close()


if __name__ == "__main__":
    main()
