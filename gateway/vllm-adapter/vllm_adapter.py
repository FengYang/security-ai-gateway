"""vllm_adapter.py — 真实 vLLM 侧密态对接适配器（4.5，M12）

运行于 TEE 内 GPU 环境，向 tee-infer 暴露统一明文推理接口，内部调用真实
vLLM 引擎生成 token IDs 回传。明文边界：本服务位于 TEE 可信域内。

接口与 Go 适配器（gateway/vllm-adapter/main.go）完全一致（平滑替换）：
    POST /generate  {"vectors":[[...]],"text":""} -> {"tokens":[...]}
    GET  /health    -> {"status":"ok","engine":"mock|vllm"}

用法：
    python vllm_adapter.py --mock                    # 本地无 GPU 验证（确定性 mock 引擎）
    python vllm_adapter.py --model Qwen2.5-7B        # 真实 vLLM（GPU + pip install vllm）

实现仅用标准库（http.server）；真实 vLLM 调用集中在 _generate_vllm，
vLLM API 随版本演进，具体调用以安装版本为准（对接骨架见 GA-vLLM密态对接设计.md）。
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _mock_generate(vectors, text):
    """确定性 mock 引擎：向量求和 mod 词表 16（与协议 token 域 0-15 对齐），本地可复现。"""
    if not vectors:
        vectors = [[0.0] * 8]
    return [int(sum(v)) % 16 for v in vectors]


class Handler(BaseHTTPRequestHandler):
    llm = None  # 真实 vLLM 引擎（--model 时初始化）
    sampling = None

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/health':
            engine = 'mock' if Handler.llm is None else 'vllm'
            self._json(200, {'status': 'ok', 'engine': engine})
        else:
            self._json(404, {'error': 'not found'})

    def do_POST(self):
        if self.path != '/generate':
            self._json(404, {'error': 'not found'})
            return
        length = int(self.headers.get('Content-Length', 0))
        try:
            req = json.loads(self.rfile.read(length) or b'{}')
        except Exception as e:  # noqa: BLE001 — 边界拒绝，不 panic
            self._json(400, {'error': f'bad json: {e}'})
            return
        vectors = req.get('vectors') or []
        text = req.get('text') or ''
        tokens = _generate(Handler.llm, Handler.sampling, vectors, text)
        self._json(200, {'tokens': tokens})

    def log_message(self, *args):  # 静默访问日志（敏感路径避免噪音）
        pass


def _generate(llm, sampling, vectors, text):
    if llm is not None:
        return _generate_vllm(llm, sampling, text)
    return _mock_generate(vectors, text)


def _generate_vllm(llm, sampling, text):
    """真实 vLLM 生成（GPU 环境）→ token ID 列表。

    方案 C（4.5）：TEE 侧采样——vLLM 返回 logits 或原始采样 token，
    最终 token 由 TEE 侧确认并加密回传；此处为对接骨架示例。
    """
    out = llm.generate([text], sampling)
    return list(out[0].outputs[0].token_ids)


def main():
    ap = argparse.ArgumentParser(description='vLLM 密态对接适配器（TEE 内）')
    ap.add_argument('--listen', default=':19190', help='监听地址')
    ap.add_argument('--mock', action='store_true', help='mock 引擎（本地无 GPU 验证）')
    ap.add_argument('--model', default='', help='真实 vLLM 模型（需 GPU + vllm 安装）')
    args = ap.parse_args()

    if not args.mock and args.model:
        from vllm import LLM, SamplingParams  # 延迟导入：无 GPU 环境不加载
        Handler.llm = LLM(model=args.model)
        Handler.sampling = SamplingParams(max_tokens=32)

    host, _, port = args.listen.partition(':')
    srv = ThreadingHTTPServer((host or '0.0.0.0', int(port)), Handler)
    engine = 'mock' if args.mock else 'vllm'
    print(f'vllm-adapter ready on {args.listen} engine={engine}')
    srv.serve_forever()


if __name__ == '__main__':
    main()
