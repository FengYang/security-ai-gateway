import paramiko

HOST = "192.168.31.166"
USER = "root"
PASS = "yf0537"


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

    pod = "tee-infer-service-cbb9ddc5f-tpxng"

    print("=== 所有 output_guard 相关 metrics ===")
    rc, out, _ = run(c, f"kubectl exec -n otpmask {pod} -- wget -qO- http://127.0.0.1:19090/metrics 2>&1 | grep -E 'otpmask_output_guard'")
    print(out)

    # 直接从节点 curl 侧车，看完整的 HTTP 交互（用 netcat 或 Python）
    print("\n=== 用 Python requests 测侧车（模拟 Go HTTP client）===")
    rc, out, _ = run(c, """
    /opt/og16-g4/venv/bin/python3 -c "
import httpx
r = httpx.post('http://127.0.0.1:19112/classify', json={'text': 'hello'}, timeout=5.0)
print(f'status={r.status_code}')
print(f'headers={dict(r.headers)}')
print(f'body={r.text[:200]}')
" 2>&1
    """)
    print(out)

    c.close()


if __name__ == "__main__":
    main()
