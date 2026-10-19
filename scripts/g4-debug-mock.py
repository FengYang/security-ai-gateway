import os
import paramiko

HOST = "192.168.31.166"
USER = "root"
PASS = os.environ.get("SSH_PASSWORD")
if not PASS:
    raise SystemExit("[FATAL] 环境变量 SSH_PASSWORD 未设置（口令仅经环境变量注入，严禁硬编码/入库）")


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

    # 用 -v 看详细响应
    print("=== curl -v /classify ===")
    rc, out, err = run(c, """
    curl -v -X POST http://127.0.0.1:19112/classify \
      -H 'Content-Type: application/json' \
      -d '{"text": "hello"}' 2>&1 | head -40
    """)
    print(out[:2000])

    # 用 Python httpx 测试（更准确）
    print("\n=== Python httpx 测试 ===")
    rc, out, _ = run(c, """
    /opt/og16-g4/venv/bin/python -c "
import httpx
r = httpx.post('http://127.0.0.1:19112/classify', json={'text': 'hello'}, timeout=5)
print('status:', r.status_code)
print('headers:', dict(r.headers))
print('body:', repr(r.text[:300]))
"
    """)
    print(out)

    c.close()


if __name__ == "__main__":
    main()
