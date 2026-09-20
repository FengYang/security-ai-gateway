import paramiko
import time

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

    # 先确认 deployment 层面 volumes 已经移除
    print("=== deployment 层面验证 ===")
    rc, out, _ = run(c, "kubectl get deploy -n otpmask tee-infer-service -o jsonpath='{.spec.template.spec.volumes}' | python3 -c \"import sys,json; v=json.load(sys.stdin); print('volumes:', json.dumps(v) if v else '(none)')\"")
    print(f"  {out.strip()}")

    # 强制滚动重启
    print("\n=== 强制滚动重启 deployment ===")
    rc, out, _ = run(c, "kubectl rollout restart deploy/tee-infer-service -n otpmask 2>&1")
    print(f"  {out.strip()}")

    # 等待新 pod
    print("\n  等待新 pod...")
    old_pod = "tee-infer-service-67f6758c6-fslgj"
    for i in range(30):
        time.sleep(3)
        rc, out, _ = run(c, "kubectl get pods -n otpmask | grep tee-infer | grep -v Terminating")
        lines = [l for l in out.strip().split("\n") if l.strip()]
        if lines:
            pod_name = lines[0].split()[0]
            if pod_name != old_pod and "1/1" in lines[0] and "Running" in lines[0]:
                print(f"  第 {i+1} 次检查：新 pod {pod_name} 就绪 ✅")
                # 验证 volumes
                rc, vols, _ = run(c, f"kubectl get pod -n otpmask {pod_name} -o jsonpath='{{.spec.volumes}}' | python3 -c \"import sys,json; v=json.load(sys.stdin); print(len(v), 'volumes') if v else print('no volumes')\"")
                print(f"  pod volumes: {vols.strip()}")
                # 验证模式
                rc, mode, _ = run(c, f"kubectl logs -n otpmask {pod_name} 2>&1 | grep '输出侧内容审查模式' | head -1")
                print(f"  模式: {mode.strip()}")
                break
        rc, all_out, _ = run(c, "kubectl get pods -n otpmask | grep tee-infer")
        print(f"  第 {i+1} 次检查:")
        for l in all_out.strip().split("\n"):
            print(f"    {l[:80]}")

    c.close()


if __name__ == "__main__":
    main()
