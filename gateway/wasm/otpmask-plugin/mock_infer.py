"""mock-infer：模拟云端密态推理服务（M3 版本）+ 本地 ai-proxy 验证端点。

行为：
  1. 接收网关转发的密文请求 {"cipher_vectors": [[...]], "nonce": "...", "model": "..."}
  2. 在"密文域"执行加法同态运算：cipher_output = cipher_vectors[0] + DELTA
     （模拟模型线性输出偏置；OTP-Mask 加法同态保证网关可正确解密为 x + DELTA）
  3. 校验输入向量维度一致性（不一致返回 400）
  4. 返回密文响应 {"cipher_output": [...], "nonce": "..."}

本地 ai-proxy 验证端点（明文协议，GF.3.2，见 deploy/higress/README.md §9）：
  POST /v1/chat/completions  OpenAI 兼容协议（openai provider 的转换目标）
  POST /v1/messages          Claude 协议（claude provider 的转换目标）
  两个端点校验 ai-proxy 已注入的厂商鉴权头（openai=Authorization: Bearer，
  claude=x-api-key，见 ai-proxy claude.go 的 standard 模式），按请求 stream 标志
  返回 OpenAI/Claude 的 SSE 或 JSON，
  供 higress-standalone 网关上的 ai-proxy 插件链做端到端验证（协议改写/鉴权注入/SSE 透传）。

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
        # 本地 ai-proxy 验证端点（明文 OpenAI/Claude 协议，非密态链路）
        if self.path.startswith("/v1/chat/completions"):
            self._handle_openai_chat()
            return
        if self.path.startswith("/v1/messages"):
            self._handle_claude_messages()
            return

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

    # ---- 本地 ai-proxy 验证端点（OpenAI/Claude 兼容协议） ----

    def _require_auth(self, provider: str) -> bool:
        """校验 ai-proxy 已注入厂商鉴权头（未注入返回 False 并回 401）。

        openai provider 注入 Authorization: Bearer <key>；
        claude provider（standard 模式）注入 x-api-key 并删除 Authorization（见 ai-proxy claude.go）。
        """
        if provider == "claude":
            if self.headers.get("x-api-key"):
                return True
            self.send_error(401, f"missing x-api-key ({provider} key not injected by ai-proxy?)")
            return False
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self.send_error(401, f"missing bearer token ({provider} key not injected by ai-proxy?)")
            return False
        return True

    def _handle_openai_chat(self):
        raw = self._read_body()
        try:
            body = json.loads(raw)
        except json.JSONDecodeError as e:
            self.send_error(400, f"bad json: {e}")
            return
        if not self._require_auth("openai"):
            return
        model = body.get("model", "mock-model")
        print(
            f"[mock-openai] path={self.path} host={self.headers.get('Host')} "
            f"stream={body.get('stream', False)} model={model}",
            flush=True,
        )
        if body.get("stream"):
            self._send_openai_sse(model)
        else:
            self._send_json({
                "id": "chatcmpl-mock",
                "object": "chat.completion",
                "created": 1725400000,
                "model": model,
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "mock reply from openai-compat endpoint"},
                    "finish_reason": "stop",
                }],
                "usage": {"prompt_tokens": 10, "completion_tokens": 6, "total_tokens": 16},
            })

    def _send_openai_sse(self, model: str):
        chunks = [
            {"id": "chatcmpl-mock", "object": "chat.completion.chunk", "created": 1725400000,
             "model": model,
             "choices": [{"index": 0, "delta": {"role": "assistant", "content": "Hello"},
                          "finish_reason": None}]},
            {"id": "chatcmpl-mock", "object": "chat.completion.chunk", "created": 1725400000,
             "model": model,
             "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
        ]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        for c in chunks:
            self.wfile.write(b"data: " + json.dumps(c).encode() + b"\n\n")
            self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def _handle_claude_messages(self):
        raw = self._read_body()
        try:
            body = json.loads(raw)
        except json.JSONDecodeError as e:
            self.send_error(400, f"bad json: {e}")
            return
        if not self._require_auth("claude"):
            return
        model = body.get("model", "claude-mock")
        print(
            f"[mock-claude] path={self.path} host={self.headers.get('Host')} "
            f"anthropic-version={self.headers.get('anthropic-version')} "
            f"stream={body.get('stream', False)} model={model}",
            flush=True,
        )
        if body.get("stream"):
            self._send_claude_sse(model)
        else:
            self._send_json({
                "id": "msg_mock",
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [{"type": "text", "text": "mock reply from claude endpoint"}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 10, "output_tokens": 5},
            })

    def _send_claude_sse(self, model: str):
        events = [
            ("message_start", {"type": "message_start", "message": {
                "id": "msg_mock", "type": "message", "role": "assistant", "model": model,
                "content": [], "usage": {"input_tokens": 10, "output_tokens": 1}}}),
            ("content_block_start", {"type": "content_block_start", "index": 0,
                                     "content_block": {"type": "text", "text": ""}}),
            ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                     "delta": {"type": "text_delta", "text": "Hello from claude mock"}}),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            ("message_delta", {"type": "message_delta",
                               "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                               "usage": {"output_tokens": 5}}),
            ("message_stop", {"type": "message_stop"}),
        ]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        for name, data in events:
            self.wfile.write(f"event: {name}\n".encode())
            self.wfile.write(b"data: " + json.dumps(data).encode() + b"\n\n")
            self.wfile.flush()

    def _send_json(self, resp: dict):
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
