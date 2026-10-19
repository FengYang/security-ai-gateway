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

    # 先杀掉当前 mock 侧车
    print("=== 重启 mock 侧车（开启请求日志）===")
    run(c, "pkill -f 'mock-sidecar.py' 2>/dev/null; sleep 1")

    # 上传带日志的新版本
    new_code = r'''
#!/usr/bin/env python3
import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

LOG_FILE = "/opt/og16-g4/sidecar/access.log"

class MockSidecarHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        try:
            with open(LOG_FILE, "a") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {format % args}\n")
        except:
            pass

    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "mode": "mock-always-block"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        # 记录所有请求头
        try:
            with open(LOG_FILE, "a") as f:
                f.write(f"\n=== POST {self.path} ===\n")
                for k, v in self.headers.items():
                    f.write(f"  {k}: {v}\n")
        except:
            pass

        if self.path != "/classify":
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            body = self.rfile.read(content_length)
            try:
                with open(LOG_FILE, "a") as f:
                    f.write(f"  body: {body.decode('utf-8', errors='replace')[:200]}\n")
            except:
                pass

        light = json.dumps({"blocked": True}, ensure_ascii=False) + "\n"
        full = json.dumps({
            "blocked": True,
            "category": "Violent",
            "confidence": 1.0,
            "match": "mock hit",
        }, ensure_ascii=False) + "\n"
        body_bytes = (light + full).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()

        try:
            time.sleep(0.05)
            self.wfile.write(light.encode())
            self.wfile.flush()
            time.sleep(0.1)
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

    # 清空日志
    open(LOG_FILE, "w").close()

    server = HTTPServer((args.host, args.port), MockSidecarHandler)
    print(f"[mock-sidecar] starting on {args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[mock-sidecar] stopped")

if __name__ == "__main__":
    main()
'''

    # 写入新脚本
    sftp = c.open_sftp()
    with sftp.file("/opt/og16-g4/sidecar/mock-sidecar-debug.py", "w") as f:
        f.write(new_code)
    sftp.close()

    # 启动
    run(c, "nohup /opt/og16-g4/venv/bin/python3 /opt/og16-g4/sidecar/mock-sidecar-debug.py --port 19112 > /opt/og16-g4/sidecar/debug.log 2>&1 &")
    time.sleep(2)

    # 确认启动
    rc, out, _ = run(c, "curl -s http://127.0.0.1:19112/healthz")
    print(f"  healthz: {out.strip()}")

    # 先等一下，然后发一个测试请求（通过 tee-infer）
    time.sleep(1)

    # 通过 Higress 发请求
    rc, key, _ = run(c, "kubectl get wasmplugin key-auth -n higress-system -o jsonpath='{.spec.defaultConfig.consumers[0].credential}'")
    api_key = key.strip()

    run(c, """
cat > /tmp/test.json << 'EOF'
{"messages":[{"role":"user","content":"hi"}],"stream":true,"engine_type":"cmaas"}
EOF
""")

    print("\n=== 通过 Higress 发测试请求 ===")
    rc, out, _ = run(c, f"""
    curl -sS -N -X POST http://127.0.0.1:18080/v1/infer \
      -H 'x-api-key: {api_key}' \
      -H 'Content-Type: application/json' \
      -H 'Accept: text/event-stream' \
      --data-binary @/tmp/test.json \
      --max-time 15 2>&1 | head -20
    """, timeout=20)
    print(out[:1000])

    # 查看 mock 侧车收到的请求
    print("\n=== mock 侧车 access.log ===")
    rc, out, _ = run(c, "cat /opt/og16-g4/sidecar/access.log 2>&1")
    print(out[:2000])

    c.close()


if __name__ == "__main__":
    main()
