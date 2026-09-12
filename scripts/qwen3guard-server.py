#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""qwen3guard-server.py —— Qwen3Guard-Gen 真实模型的 OpenAI 兼容服务（CPU 推理）

用途：为 Higress `qwen3guard` 插件提供**真实模型**判定（无需 GPU、无云依赖，满足内网部署）。
      与 scripts/stub-qwen3guard.py 契约完全一致，可互换（同一端口、同一响应格式）。

契约（与插件 guard.go / body.go 对齐，勿改）：
  - 入参：{"model": ..., "messages": [{"role": "user"|"assistant", "content": ...}], "max_tokens": 128}
  - 出参：HTTP 200 + OpenAI 兼容 JSON，判定文本位于 choices[0].message.content，
    且需匹配 (?mi)^Safety:\\s*(Safe|Unsafe|Controversial)\\b（Safety 行首）。
  - 插件解析不出 Safety 即 fail-open（放行）——若联调"全部放行"，先查本服务输出。

模型：Qwen/Qwen3Guard-Gen-0.6B（ModelScope）。下载：
  python -c "from modelscope import snapshot_download; snapshot_download('Qwen/Qwen3Guard-Gen-0.6B', local_dir='.tools/models/Qwen3Guard-Gen-0.6B')"

用法：
  python scripts/qwen3guard-server.py                      # 默认 .tools/models/Qwen3Guard-Gen-0.6B，端口 19100
  python scripts/qwen3guard-server.py --port 19100 --max-new-tokens 64
"""
import argparse
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = None
TOKENIZER = None
LOCK = threading.Lock()
MAX_NEW_TOKENS = 64
CALLS = 0


def load_model(model_dir, dtype_name):
    global MODEL, TOKENIZER
    import torch  # noqa: PLC0415
    from transformers import AutoModelForCausalLM, AutoTokenizer  # noqa: PLC0415

    dtype = {"float32": torch.float32, "float16": torch.float16, "bfloat16": torch.bfloat16}[dtype_name]
    print("[qwen3guard] loading model from %s (device=cpu, dtype=%s) ..." % (model_dir, dtype_name), flush=True)
    t0 = time.time()
    TOKENIZER = AutoTokenizer.from_pretrained(model_dir)
    MODEL = AutoModelForCausalLM.from_pretrained(model_dir, torch_dtype=dtype, low_cpu_mem_usage=True)
    MODEL.eval()
    print("[qwen3guard] model loaded in %.1fs" % (time.time() - t0), flush=True)


def generate(messages):
    import torch  # noqa: PLC0415

    text = TOKENIZER.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = TOKENIZER([text], return_tensors="pt")
    with LOCK, torch.no_grad():
        out = MODEL.generate(
            **inputs,
            max_new_tokens=MAX_NEW_TOKENS,
            do_sample=False,
            pad_token_id=TOKENIZER.pad_token_id or TOKENIZER.eos_token_id,
        )
    gen = out[0][inputs["input_ids"].shape[1]:]
    return TOKENIZER.decode(gen, skip_special_tokens=True)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path.rstrip("/") in ("/healthz", "/"):
            self._send(200, {"status": "ok", "backend": "qwen3guard-gen-real", "model_loaded": MODEL is not None})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        global CALLS
        if not self.path.rstrip("/").endswith("/chat/completions"):
            self._send(404, {"error": "not found", "path": self.path})
            return
        length = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw.decode("utf-8", "replace"))
        except Exception as exc:  # noqa: BLE001
            self._send(400, {"error": "bad json: %s" % exc})
            return

        messages = req.get("messages") or []
        t0 = time.time()
        try:
            content = generate(messages)
        except Exception as exc:  # noqa: BLE001
            # 推理失败 → 返回非 200，让插件按其 fail-open 语义处理（并在日志暴露）
            self._send(500, {"error": "inference failed: %s" % exc})
            return
        dt = time.time() - t0
        CALLS += 1
        print("[qwen3guard] call#%d %.1fs model=%s -> %r" % (CALLS, dt, req.get("model"), content[:80]), flush=True)

        self._send(200, {
            "id": "chatcmpl-real-%d" % CALLS,
            "object": "chat.completion",
            "model": req.get("model") or "Qwen/Qwen3Guard-Gen-0.6B",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        })

    def log_message(self, fmt, *args):
        return


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model-dir", default=os.path.join(".tools", "models", "Qwen3Guard-Gen-0.6B"))
    ap.add_argument("--port", type=int, default=19100)
    ap.add_argument("--max-new-tokens", type=int, default=64)
    ap.add_argument("--dtype", default="float32", choices=["float32", "float16", "bfloat16"])
    args = ap.parse_args()

    global MAX_NEW_TOKENS
    MAX_NEW_TOKENS = args.max_new_tokens
    if not os.path.isdir(args.model_dir):
        print("[qwen3guard] model dir not found: %s" % args.model_dir, flush=True)
        return 1
    load_model(args.model_dir, args.dtype)

    srv = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print("[qwen3guard] listening on 0.0.0.0:%d (CPU inference; max_new_tokens=%d)" % (args.port, MAX_NEW_TOKENS), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("[qwen3guard] stopped", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
