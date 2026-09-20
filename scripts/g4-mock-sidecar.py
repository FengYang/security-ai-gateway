#!/usr/bin/env python3
"""
G-4 OG-16 批 5 专用：Mock L2 侧车
用途：固定返回 blocked=true，用于触发 tee-infer 的 content_filter 终止帧，
     验证 Higress otpmask 插件全链路的终止帧识别与透传。

接口协议与真侧车完全一致（两段式 v2）：
  POST /classify
  Body: {"text": "..."}
  Response（流式，换行分隔两 JSON 文档）:
    文档 1（轻段）: {"blocked": true}
    文档 2（完整段）: {"blocked": true, "category": "Violent", "confidence": 1.0, "match": "mock hit"}

同时支持 GET /healthz 健康检查。
"""
import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

MOCK_BLOCKED = True
MOCK_CATEGORY = "Violent"
MOCK_CONFIDENCE = 1.0
MOCK_MATCH = "mock hit"
MOCK_LIGHT_DELAY = 0.05  # 模拟轻段延迟（50ms）
MOCK_FULL_DELAY = 0.1    # 模拟完整段延迟（再加 100ms）


class MockSidecarHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # 安静模式
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
        if self.path != "/classify":
            self.send_response(404)
            self.end_headers()
            return

        # 读取 body（不解析，mock 固定返回）
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            self.rfile.read(content_length)

        # 两段式响应（HTTP/1.0 兼容，用 Content-Length）
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

        # 先发送轻段，模拟早出（tee-infer 适配层逐行读，能感知到两段）
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
    print(f"[mock-sidecar] starting on {args.host}:{args.port} (always blocked=true, category={MOCK_CATEGORY})")
    print(f"[mock-sidecar] GET /healthz  POST /classify")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[mock-sidecar] stopped")


if __name__ == "__main__":
    main()
