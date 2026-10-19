import os
import paramiko
import time

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

    # 杀掉当前 debug 侧车，启动返回 A1-06 类目的侧车
    print("=== 重启 mock 侧车（category=A1-06）===")
    run(c, "pkill -f 'mock-sidecar' 2>/dev/null; sleep 1")

    new_code = r'''
#!/usr/bin/env python3
"""Mock L2 sidecar: always blocked, category=A1-06 (internal ID)"""
import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

MOCK_BLOCKED = True
MOCK_CATEGORY = "A1-06"  # tee-infer 内部类目 ID：宣扬暴力、淫秽色情
MOCK_CONFIDENCE = 0.95
MOCK_MATCH = "mock violence hit"
MOCK_LIGHT_DELAY = 0.02
MOCK_FULL_DELAY = 0.05

class MockSidecarHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # quiet

    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "mode": "mock-always-block-A106"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path != "/classify":
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            self.rfile.read(content_length)

        light = json.dumps({"blocked": MOCK_BLOCKED}, ensure_ascii=False) + "\n"
        full = json.dumps({
            "blocked": MOCK_BLOCKED,
            "category": MOCK_CATEGORY,
            "confidence": MOCK_CONFIDENCE,
            "match": MOCK_MATCH,
        }, ensure_ascii=False) + "\n"
        body = (light + full).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

        try:
            time.sleep(MOCK_LIGHT_DELAY)
            self.wfile.write(light.encode())
            self.wfile.flush()
            time.sleep(MOCK_FULL_DELAY)
            self.wfile.write(full.encode())
            self.wfile.flush()
        except BrokenPipeError:
            pass

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=19112)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()
    server = HTTPServer((args.host, args.port), MockSidecarHandler)
    print(f"[mock-sidecar] {args.host}:{args.port} (always blocked, category=A1-06)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[mock-sidecar] stopped")

if __name__ == "__main__":
    main()
'''

    sftp = c.open_sftp()
    with sftp.file("/opt/og16-g4/sidecar/mock-sidecar-a106.py", "w") as f:
        f.write(new_code)
    sftp.close()

    run(c, "nohup /opt/og16-g4/venv/bin/python3 /opt/og16-g4/sidecar/mock-sidecar-a106.py --port 19112 > /opt/og16-g4/sidecar/a106.log 2>&1 &")
    time.sleep(2)

    # 验证
    rc, out, _ = run(c, "curl -s http://127.0.0.1:19112/healthz")
    print(f"  healthz: {out.strip()}")

    rc, out, _ = run(c, "curl -s -X POST http://127.0.0.1:19112/classify -H 'Content-Type: application/json' -d '{\"text\":\"test\"}'")
    print(f"  classify: {out.strip()}")

    c.close()
    print("\n✅ mock 侧车已更新为 category=A1-06")


if __name__ == "__main__":
    main()
