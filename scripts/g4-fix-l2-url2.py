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

    # 先获取完整的 container spec
    rc, spec_json, _ = run(c, "kubectl get deploy -n otpmask tee-infer-service -o jsonpath='{.spec.template.spec.containers[0]}'")

    # 用 sed 或者直接写 python 修改
    # 更简单：用 kubectl patch --type=strategic 提供完整 container（含 name）
    print("=== patch deployment（strategic merge）===")

    # 获取 image
    rc, image, _ = run(c, "kubectl get deploy -n otpmask tee-infer-service -o jsonpath='{.spec.template.spec.containers[0].image}'")
    print(f"  image: {image.strip()}")

    # 构造 patch YAML（用 YAML 字符串更简单）
    patch_yaml = f"""
spec:
  template:
    spec:
      containers:
      - name: tee-infer-service
        image: {image.strip()}
        args:
        - -sig-key
        - $(SIG_KEY)
        - -attest-token
        - $(ATTEST_TOKEN)
        - -output-guard
        - enforcing
        - -output-guard-policy-dir
        - /app/policy
        - -output-guard-l2-url
        - http://qwen3guard-l2.otpmask:19112/classify
        - -output-guard-l2-allowed-cidrs
        - 192.168.31.166/32,10.43.0.0/16
        - -cmaas-url
        - $(CMAAS_URL)
        - -cmaas-model
        - $(CMAAS_MODEL)
"""

    # 写入文件再 patch
    sftp = c.open_sftp()
    with sftp.file("/tmp/l2-url-patch.yaml", "w") as f:
        f.write(patch_yaml)
    sftp.close()

    rc, out, err = run(c, "kubectl patch deploy -n otpmask tee-infer-service --patch-file /tmp/l2-url-patch.yaml 2>&1")
    print(f"  {out.strip()}")
    if err.strip() and "patched" not in out:
        print(f"  err: {err.strip()}")

    # 等待新 pod 启动
    print("\n=== 等待新 pod ===")
    old_pod = ""
    rc, out, _ = run(c, "kubectl get pods -n otpmask | grep tee-infer | grep Running | grep -v Terminating | awk '{print $1}'")
    old_pod = out.strip()
    print(f"  旧 pod: {old_pod}")

    new_pod = ""
    for i in range(40):
        time.sleep(3)
        rc, out, _ = run(c, "kubectl get pods -n otpmask | grep tee-infer | grep Running | grep -v Terminating | grep -v ContainerCreating | awk '{print $1}'")
        pods = [p for p in out.strip().split("\n") if p.strip()]
        if pods and pods[0] != old_pod:
            new_pod = pods[0]
            print(f"  第 {i+1} 次检查：新 pod {new_pod} 出现")
            # 等 1/1 Running
            rc, out, _ = run(c, f"kubectl get pod -n otpmask {new_pod} -o jsonpath='{{.status.containerStatuses[0].ready}}'")
            if out.strip() == "true":
                print(f"  新 pod ready")
                break
        else:
            # 看有几个 pod
            rc, out, _ = run(c, "kubectl get pods -n otpmask | grep tee-infer")
            lines = [l for l in out.strip().split("\n") if l.strip()]
            print(f"  第 {i+1} 次检查：{len(lines)} 个 pod")
            for l in lines:
                print(f"    {l[:80]}")

    time.sleep(3)

    # 验证新参数
    print("\n=== 验证 L2 URL ===")
    rc, out, _ = run(c, f"kubectl logs -n otpmask {new_pod} 2>&1 | grep 'L2 语义分类器接线' | head -1")
    print(f"  {out.strip()}")

    c.close()


if __name__ == "__main__":
    main()
