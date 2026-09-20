import paramiko
import time
from pathlib import Path

HOST = "192.168.31.166"
USER = "root"
PASS = "yf0537"

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

    # 1. 上传 mock 侧车
    print("=== 1. 上传 mock 侧车 ===")
    sftp.put(str(LOCAL_MOCK), REMOTE_MOCK)
    print(f"  上传完成: {REMOTE_MOCK}")

    # 2. 杀掉旧侧车/llama 进程
    run(c, "pkill -f 'sidecar\\|llama' 2>/dev/null; sleep 1")

    # 3. 启动 mock 侧车
    print("\n=== 2. 启动 mock 侧车 ===")
    run(c, f"""
    nohup /opt/og16-g4/venv/bin/python {REMOTE_MOCK} --port 19112 \
      > /opt/og16-g4/mock-sidecar.log 2>&1 &
    echo "PID=$!"
    """)
    time.sleep(2)

    # 检查进程
    rc, out, _ = run(c, "ps aux | grep mock-sidecar | grep -v grep | head -3")
    print(f"  进程: {out.strip() or '(未找到)'}")

    # 4. 健康检查
    print("\n=== 3. 健康检查 ===")
    for i in range(5):
        time.sleep(1)
        rc, out, _ = run(c, "curl -s http://127.0.0.1:19112/healthz")
        if rc == 0 and "ok" in out:
            print(f"  ✅ 就绪: {out.strip()}")
            break
    else:
        print(f"  ❌ 未就绪")
        rc, out, _ = run(c, "tail -20 /opt/og16-g4/mock-sidecar.log")
        print(out)

    # 5. 测试 classify 接口
    print("\n=== 4. 测试 classify ===")
    rc, out, _ = run(c, """
    curl -s -X POST http://127.0.0.1:19112/classify \
      -H 'Content-Type: application/json' \
      -d '{"text": "test"}'
    """)
    print(f"  响应 ({len(out)} bytes):")
    print("  " + out.strip().replace("\n", "\n  "))

    sftp.close()
    c.close()
    print("\n✅ Mock 侧车就绪")


if __name__ == "__main__":
    main()
