import os
import paramiko
from pathlib import Path

HOST = "192.168.31.166"
USER = "root"
PASS = os.environ.get("SSH_PASSWORD")
if not PASS:
    raise SystemExit("[FATAL] 环境变量 SSH_PASSWORD 未设置（口令仅经环境变量注入，严禁硬编码/入库）")

LOCAL_YAML = Path(r"c:\Users\Robin\Desktop\方案\security-ai-gateway\scripts\g4-service.yaml")
REMOTE_YAML = "/opt/og16-g4/service.yaml"


def run(c, cmd, timeout=60):
    print(f"$ {cmd[:120]}")
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    if out.strip():
        print(out.rstrip())
    if err.strip() and "Warning" not in err and "created" not in err:
        print("STDERR:", err.rstrip()[:300])
    print(f"  → exit {rc}\n")
    return rc, out, err


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    sftp = c.open_sftp()

    # 上传 YAML
    sftp.put(str(LOCAL_YAML), REMOTE_YAML)
    print(f"上传: {REMOTE_YAML}")

    # apply
    print("=== kubectl apply ===")
    run(c, f"kubectl apply -f {REMOTE_YAML}")

    # 验证
    print("=== 验证 Service ===")
    run(c, "kubectl get svc qwen3guard-l2 -n otpmask -o wide")
    run(c, "kubectl get endpoints qwen3guard-l2 -n otpmask")

    # 从 pod 里测试侧车连通性
    print("=== 从 tee-infer pod 测试侧车连通性 ===")
    run(c, "kubectl exec -n otpmask deploy/tee-infer-service -- curl -s http://qwen3guard-l2:19112/healthz 2>&1")

    sftp.close()
    c.close()


if __name__ == "__main__":
    main()
