"""mock-infer：模拟云端密态推理服务（M3 版本）。

行为：
  1. 接收网关转发的密文请求 {"cipher_vectors": [[...]], "nonce": "...", "model": "..."}
  2. 在"密文域"执行加法同态运算：cipher_output = cipher_vectors[0] + DELTA
     （模拟模型线性输出偏置；OTP-Mask 加法同态保证网关可正确解密为 x + DELTA）
  3. 校验输入向量维度一致性（不一致返回 400）
  4. 返回密文响应 {"cipher_output": [...], "nonce": "..."}

DELTA 由环境变量 MOCK_DELTA 控制（默认 7，设为 0 即恒等返回）。

仅使用标准库，无第三方依赖。
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os

DELTA = int(os.environ.get("MOCK_DELTA", "7"))


class Handler(BaseHTTPRequestHandler):
    # HTTP/1.1：网关移除 Content-Length 后用 chunked 上传密文 body，
    # 仅 HTTP/1.0 后端不支持 chunked，导致 body 读空（bad json）。
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        print(f"[mock-infer] HEADERS={dict(self.headers)}", flush=True)
        raw = self._read_body()
        print(f"[mock-infer] RAW({len(raw)}B)={raw!r}", flush=True)
        try:
            body = json.loads(raw)
        except json.JSONDecodeError as e:
            self.send_error(400, f"bad json: {e}")
            return

        cipher_vectors = body.get("cipher_vectors", [])
        nonce = body.get("nonce", "")
        if not cipher_vectors:
            self.send_error(400, "missing cipher_vectors")
            return

        # 维度一致性校验（密文域）
        dims = {len(v) for v in cipher_vectors}
        if len(dims) > 1:
            self.send_error(400, f"inconsistent dimensions: {sorted(dims)}")
            return

        # 密文域加法同态：模拟模型输出偏置
        cipher_output = [(c + DELTA) % (1 << 32) for c in cipher_vectors[0]]
        print(
            f"[mock-infer] COMPUTED delta={DELTA} nonce={nonce[:8]} "
            f"cipher_output={cipher_output[:3]}...",
            flush=True,
        )

        resp = {"cipher_output": cipher_output, "nonce": nonce}
        data = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.wfile.flush()

    def _read_body(self) -> bytes:
        """读取请求体：支持 Content-Length 与 chunked 两种传输编码。"""
        te = self.headers.get("Transfer-Encoding", "").lower()
        if te == "chunked":
            chunks = []
            while True:
                size_line = self.rfile.readline().strip()
                try:
                    size = int(size_line.split(b";")[0], 16)
                except ValueError:
                    return b""
                if size == 0:
                    self.rfile.readline()  # 尾部 CRLF
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.read(2)  # chunk 后 CRLF
            return b"".join(chunks)
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length)

    def log_message(self, fmt, *args):
        pass  # 静默访问日志，仅保留业务 print


if __name__ == "__main__":
    print(f"[mock-infer] starting, MOCK_DELTA={DELTA}", flush=True)
    HTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
