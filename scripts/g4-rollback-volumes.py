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

    print("=== 移除 hostPath volumes 和 volumeMounts ===")

    # 用 JSON patch 移除 volumes 和 volumeMounts
    patch = r'''[
    {"op":"remove","path":"/spec/template/spec/volumes"},
    {"op":"remove","path":"/spec/template/spec/containers/0/volumeMounts"}
]'''

    rc, out, err = run(c, f"kubectl patch deploy -n otpmask tee-infer-service --type=json -p '{patch}' 2>&1")
    print(f"  patch: {out.strip()}")
    if err.strip() and "patched" not in out:
        print(f"  err: {err.strip()}")

    # 等待新 pod
    print("\n  等待新 pod...")
    for i in range(30):
        time.sleep(3)
        rc, out, _ = run(c, "kubectl get pods -n otpmask | grep tee-infer | grep -v Terminating | grep -v ContainerCreating")
        lines = [l for l in out.strip().split("\n") if l.strip()]
        if lines and "1/1" in lines[0] and "Running" in lines[0]:
            pod_name = lines[0].split()[0]
            print(f"  第 {i+1} 次检查：{pod_name} 就绪 ✅")
            # 验证没有 hostPath
            rc, vols, _ = run(c, f"kubectl get pod -n otpmask {pod_name} -o jsonpath='{{.spec.volumes}}' | python3 -c \"import sys,json; v=json.load(sys.stdin); print(len(v), 'volumes') if v else print('no volumes')\"")
            print(f"  volumes: {vols.strip()}")
            break
        rc, all_out, _ = run(c, "kubectl get pods -n otpmask | grep tee-infer")
        print(f"  第 {i+1} 次检查:")
        for l in all_out.strip().split("\n"):
            print(f"    {l[:80]}")

    # 最终验证
    time.sleep(2)
    print("\n=== 最终验证 ===")
    rc, out, _ = run(c, "kubectl get deploy -n otpmask tee-infer-service -o jsonpath='{.spec.template.spec.containers[0].args}' | python3 -c \"import sys,json; print('args:', json.load(sys.stdin))\"")
    print(f"  {out.strip()}")
    rc, out, _ = run(c, "kubectl get deploy -n otpmask tee-infer-service -o jsonpath='{.spec.template.spec.volumes}' | python3 -c \"import sys,json; v=json.load(sys.stdin); print('volumes:', len(v) if v else 0)\"")
    print(f"  {out.strip()}")

    c.close()
    print("\n✅ 完全回滚完成")


if __name__ == "__main__":
    main()
