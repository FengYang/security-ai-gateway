import paramiko
import time

HOST = "192.168.31.166"
USER = "root"
PASS = "yf0537"


def run(c, cmd, timeout=60):
    print(f"$ {cmd[:120]}")
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    if out.strip():
        print(out.rstrip()[:2000])
    if err.strip() and "Warning" not in err and "created" not in err and "configured" not in err and "patched" not in err:
        print("STDERR:", err.rstrip()[:500])
    print(f"  → exit {rc}\n")
    return rc, out, err


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)

    # 执行 patch
    print("=== 1. 执行 kubectl patch ===")
    rc, out, _ = run(c, "bash /opt/og16-g4/patch-deploy.sh")
    if rc != 0:
        print("❌ patch 失败！")
        c.close()
        return

    # 等待新 pod 启动
    print("=== 2. 等待新 pod 启动 ===")
    for i in range(30):
        time.sleep(3)
        rc, out, _ = run(c, "kubectl get pods -n otpmask -l app=tee-infer-service 2>/dev/null || kubectl get pods -n otpmask | grep tee-infer")
        lines = [l for l in out.strip().split('\n') if 'tee-infer' in l]
        status_line = lines[0] if lines else ''
        print(f"  ({i*3}s) {status_line}")
        if 'Running' in status_line and '1/1' in status_line:
            print("  ✅ Pod 就绪")
            break
        if 'CrashLoopBackOff' in status_line or 'Error' in status_line:
            print("  ❌ Pod 启动失败！")
            rc, logs, _ = run(c, f"kubectl logs -n otpmask {status_line.split()[0]} --tail=50")
            print("日志:", logs[-2000:])
            c.close()
            return
    else:
        print("  ⚠️ 超时，检查日志...")

    # 看日志确认 output guard 配置
    print("\n=== 3. 查看启动日志（output-guard 相关） ===")
    rc, out, _ = run(c, "kubectl logs -n otpmask deploy/tee-infer-service 2>&1 | grep -iE 'output-guard|output_guard|l2|enforc' | head -20")
    print(out)

    c.close()


if __name__ == "__main__":
    main()
