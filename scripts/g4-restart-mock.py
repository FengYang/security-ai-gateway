import os
import paramiko
from pathlib import Path

HOST = "192.168.31.166"
USER = "root"
PASS = os.environ.get("SSH_PASSWORD")
if not PASS:
    raise SystemExit("[FATAL] 环境变量 SSH_PASSWORD 未设置（口令仅经环境变量注入，严禁硬编码/入库）")

LOCAL_MOCK = Path(r"c:\Users\Robin\Desktop\方案\security-ai-gateway\scripts\g4-mock-sidecar.py")
REMOTE_MOCK = "/opt/og16-g4/sidecar/mock-sidecar.py"


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
    sftp = c.open_sftp()

    # 上传新版本
    sftp.put(str(LOCAL_MOCK), REMOTE_MOCK)

    # 杀掉旧的
    run(c, "pkill -f mock-sidecar 2>/dev/null; sleep 1")

    # 启动新的
    run(c, f"""
    nohup /opt/og16-g4/venv/bin/python {REMOTE_MOCK} --port 19112 \
      > /opt/og16-g4/mock-sidecar.log 2>&1 &
    echo "PID=$!"
    """)
    import time
    time.sleep(2)

    # 测试
    print("=== 健康检查 ===")
    rc, out, _ = run(c, "curl -s http://127.0.0.1:19112/healthz")
    print(out.strip())

    print("\n=== /classify 测试 ===")
    rc, out, _ = run(c, """
    curl -s -X POST http://127.0.0.1:19112/classify \
      -H 'Content-Type: application/json' \
      -d '{"text": "test"}'
    """)
    print(f"响应 ({len(out)} bytes):")
    print(out.strip())

    sftp.close()
    c.close()


if __name__ == "__main__":
    main()
