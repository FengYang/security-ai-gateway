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

    print("=== 恢复 tee-infer deployment（shadow 模式）===")

    # 先看当前完整 args
    rc, args, _ = run(c, "kubectl get deploy -n otpmask tee-infer-service -o jsonpath='{.spec.template.spec.containers[0].args}' | python3 -c \"import sys,json; print(json.load(sys.stdin))\"")
    print(f"  当前 args: {args.strip()}")

    # 用 JSON patch 精确修改：改回 shadow 模式 + 移除 L2 相关参数
    patch = r'''[
    {"op":"replace","path":"/spec/template/spec/containers/0/args","value":[
        "-sig-key","$(SIG_KEY)",
        "-attest-token","$(ATTEST_TOKEN)",
        "-output-guard","shadow",
        "-output-guard-policy-dir","/app/policy",
        "-cmaas-url","$(CMAAS_URL)",
        "-cmaas-model","$(CMAAS_MODEL)"
    ]}
]'''

    rc, out, err = run(c, f"kubectl patch deploy -n otpmask tee-infer-service --type=json -p '{patch}' 2>&1")
    print(f"  patch 结果: {out.strip()}")
    if err.strip() and "patched" not in out:
        print(f"  err: {err.strip()}")

    # 同时检查并移除 hostPath volume（如果有的话）
    rc, vols, _ = run(c, "kubectl get deploy -n otpmask tee-infer-service -o jsonpath='{.spec.template.spec.volumes}' | python3 -c \"import sys,json; v=json.load(sys.stdin); print(len(v), 'volumes') if v else print('no volumes')\"")
    print(f"  volumes: {vols.strip()}")

    # 如果有 hostPath volume，需要移除（备份里可能没有，但我们之前 patch 可能加了）
    # 实际上 og11 原始镜像里就有 /app/policy，policy 不用改
    # 只需要把模式改回 shadow 就行了

    # 等待新 pod
    print("\n  等待新 pod 启动...")
    old_pod = "tee-infer-service-75c5b5fcbb-54cds"
    for i in range(30):
        time.sleep(3)
        rc, out, _ = run(c, "kubectl get pods -n otpmask | grep tee-infer | grep -v Terminating | grep -v ContainerCreating")
        lines = [l for l in out.strip().split("\n") if l.strip()]
        if lines:
            pod_name = lines[0].split()[0]
            if pod_name != old_pod and "1/1" in lines[0] and "Running" in lines[0]:
                print(f"  第 {i+1} 次检查：新 pod {pod_name} 就绪 ✅")
                # 验证模式
                time.sleep(2)
                rc, mode_line, _ = run(c, f"kubectl logs -n otpmask {pod_name} 2>&1 | grep '输出侧内容审查模式' | head -1")
                print(f"  模式: {mode_line.strip()}")
                break
        print(f"  第 {i+1} 次检查: {out.strip()[:100]}")

    c.close()


if __name__ == "__main__":
    main()
