import os
import paramiko

HOST = "192.168.31.166"
USER = "root"
PASS = os.environ.get("SSH_PASSWORD")
if not PASS:
    raise SystemExit("[FATAL] 环境变量 SSH_PASSWORD 未设置（口令仅经环境变量注入，严禁硬编码/入库）")


def run(c, cmd, timeout=60):
    print(f"$ {cmd[:120]}")
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    if out.strip():
        print(out.rstrip()[:2000])
    if err.strip() and "Warning" not in err and "created" not in err and "configured" not in err:
        print("STDERR:", err.rstrip()[:500])
    print(f"  → exit {rc}\n")
    return rc, out, err


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)

    # 1. 备份当前 deployment
    print("=== 1. 备份 tee-infer deployment ===")
    run(c, "kubectl get deploy tee-infer-service -n otpmask -o yaml > /opt/og16-g4/tee-infer-backup.yaml")
    run(c, "ls -lh /opt/og16-g4/tee-infer-backup.yaml")

    # 2. 方案：用 init container 替换二进制 + 修改 args
    # 更简单：直接把二进制放到节点上，用 hostPath 挂载替换
    # 但是 pod 里是 USER 65532，hostPath 文件是 root 的，需要权限
    # 最简单：创建一个 ConfigMap？不行，二进制 16MB 超了
    #
    # 最佳方案：重新打一个镜像，用 containerd 导入
    # 更快的方案：在节点上创建一个目录 + 改权限 + hostPath 挂载 + command 覆盖
    #
    # 让我用 hostPath 方案：
    # - 把二进制放到 /opt/og16-g4/bin/tee-infer-service
    # - policy 放到 /opt/og16-g4/policy/
    # - deployment 加 volumeMounts 覆盖 /usr/local/bin/tee-infer-service 和 /app/policy
    # - 改 args 加 enforcing + L2 URL

    # 3. 确认二进制和权限
    print("=== 2. 准备二进制和权限 ===")
    # 给 65532 用户读权限
    run(c, "chmod 755 /opt/og16-g4/bin/tee-infer-service")
    run(c, "chown -R 65532:65532 /opt/og16-g4/bin /opt/og16-g4/policy")
    run(c, "ls -la /opt/og16-g4/bin/tee-infer-service")

    # 4. 生成 patch YAML
    print("=== 3. 生成 deployment patch ===")
    # 用 kubectl patch 方式
    patch_script = r"""
kubectl patch deploy tee-infer-service -n otpmask --type=strategic --patch '
spec:
  template:
    spec:
      containers:
      - name: tee-infer-service
        image: otpmask/tee-infer-service:og11
        args:
        - "-sig-key"
        - "$(SIG_KEY)"
        - "-attest-token"
        - "$(ATTEST_TOKEN)"
        - "-output-guard"
        - "enforcing"
        - "-output-guard-policy-dir"
        - "/app/policy"
        - "-output-guard-l2-url"
        - "http://qwen3guard-l2.otpmask:19112"
        - "-output-guard-l2-allowed-cidrs"
        - "192.168.31.166/32,10.43.0.0/16"
        - "-cmaas-url"
        - "$(CMAAS_URL)"
        - "-cmaas-model"
        - "$(CMAAS_MODEL)"
        command: ["/usr/local/bin/tee-infer-service"]
        volumeMounts:
        - name: og16-bin
          mountPath: /usr/local/bin/tee-infer-service
          subPath: tee-infer-service
        - name: og16-policy
          mountPath: /app/policy
      volumes:
      - name: og16-bin
        hostPath:
          path: /opt/og16-g4/bin
          type: Directory
      - name: og16-policy
        hostPath:
          path: /opt/og16-g4/policy
          type: Directory
      securityContext:
        runAsUser: 65532
        runAsGroup: 65532
        runAsNonRoot: true
'
"""
    # 写到节点上
    sftp = c.open_sftp()
    with sftp.file("/opt/og16-g4/patch-deploy.sh", "w") as f:
        f.write("#!/bin/bash\n")
        f.write(patch_script.strip() + "\n")
    sftp.chmod("/opt/og16-g4/patch-deploy.sh", 0o755)
    sftp.close()

    print("Patch 脚本已准备: /opt/og16-g4/patch-deploy.sh")
    print("（先不执行，确认无误后再跑）")

    # 验证一下二进制能不能跑（在节点上直接跑 help）
    print("\n=== 4. 验证二进制可执行（Linux 本地）===")
    rc, out, err = run(c, "/opt/og16-g4/bin/tee-infer-service -h 2>&1 | grep -E 'output-guard|l2' | head -10", timeout=10)
    if out.strip():
        print("  输出:", out.strip())
    else:
        print("  (无 output-guard 相关输出，可能是二进制不对)")
        print("  err:", err[:300])

    c.close()


if __name__ == "__main__":
    main()
