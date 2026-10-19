import os
import paramiko
import time

HOST = "192.168.31.166"
USER = "root"
PASS = os.environ.get("SSH_PASSWORD")
if not PASS:
    raise SystemExit("[FATAL] 环境变量 SSH_PASSWORD 未设置（口令仅经环境变量注入，严禁硬编码/入库）")


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

    print("=" * 60)
    print("G-4 环境回滚")
    print("=" * 60)

    # 1. 恢复 tee-infer deployment（从备份）
    print("\n1️⃣  恢复 tee-infer deployment")
    rc, out, _ = run(c, "ls -la /opt/og16-g4/tee-infer-backup.yaml 2>&1")
    print(f"  备份文件: {out.strip()}")

    rc, out, err = run(c, "kubectl apply -f /opt/og16-g4/tee-infer-backup.yaml 2>&1")
    print(f"  apply: {out.strip()}")
    if err.strip() and "unchanged" not in out and "configured" not in out and "created" not in out:
        print(f"  err: {err.strip()}")

    # 等待旧 pod 恢复
    print("\n  等待 pod 恢复...")
    for i in range(30):
        time.sleep(3)
        rc, out, _ = run(c, "kubectl get pods -n otpmask | grep tee-infer | grep -v Terminating")
        lines = [l for l in out.strip().split("\n") if l.strip()]
        if len(lines) == 1 and "Running" in lines[0] and "1/1" in lines[0]:
            print(f"  第 {i+1} 次检查：pod 就绪 ✅")
            print(f"  {lines[0]}")
            break
        print(f"  第 {i+1} 次检查：{out.strip()[:80]}")

    # 验证恢复后的参数
    time.sleep(2)
    rc, out, _ = run(c, "kubectl logs -n otpmask deploy/tee-infer-service 2>&1 | grep '输出侧内容审查模式' | head -1")
    print(f"  当前模式: {out.strip()}")

    # 2. 删除 Service + Endpoints
    print("\n2️⃣  删除 Service + Endpoints")
    rc, out, _ = run(c, "kubectl delete svc qwen3guard-l2 -n otpmask 2>&1")
    print(f"  {out.strip()}")
    rc, out, _ = run(c, "kubectl delete endpoints qwen3guard-l2 -n otpmask 2>&1")
    print(f"  {out.strip()}")

    # 3. 停掉 mock 侧车
    print("\n3️⃣  停掉 mock 侧车")
    rc, out, _ = run(c, "pkill -f 'mock-sidecar' 2>&1; sleep 1; ps aux | grep mock-sidecar | grep -v grep | wc -l")
    print(f"  剩余进程数: {out.strip()}")

    # 4. 杀掉 port-forward
    print("\n4️⃣  杀掉 port-forward")
    rc, out, _ = run(c, "pkill -f 'kubectl port-forward' 2>&1; echo done")
    print(f"  {out.strip()}")

    # 5. 验证环境干净
    print("\n5️⃣  环境验证")
    rc, out, _ = run(c, "kubectl get svc -n otpmask | grep qwen")
    print(f"  qwen3guard-l2 service: {'存在' if out.strip() else '已删除 ✅'}")

    rc, out, _ = run(c, "kubectl get pods -n otpmask | grep tee-infer")
    print(f"  tee-infer pod: {out.strip()[:80]}")

    print("\n" + "=" * 60)
    print("✅ 回滚完成")
    print("=" * 60)

    c.close()


if __name__ == "__main__":
    main()
