#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""stub-qwen3guard.py —— Qwen3Guard-Gen 的**本地替身**（用于网关内容安全链路联调，不带真实模型）

为什么需要：Higress `qwen3guard` 插件要求一个 OpenAI 兼容的内容安全服务（POST /v1/chat/completions）；
本替身按插件的**实际解析规则**返回判定，用于在无 GPU、无真实模型的情况下验证
「请求提取 → 外呼审核 → 命中拦截/放行 → 拒答整形」全链路。

与插件的契约（依据插件源码 guard.go / body.go，逐条对齐，勿随意改）：
  - 入参：{"model": "...", "messages": [{"role": "user"|"assistant", "content": "..."}], "max_tokens": 128}
    请求检测时插件只发一条 user 消息；响应检测时发 user(原始提问)+assistant(待检回复) 两条。
  - 出参：HTTP 200 + OpenAI 兼容 JSON，**判定文本必须位于 choices[0].message.content**，
    且匹配 (?mi)^Safety:\\s*(Safe|Unsafe|Controversial)\\b —— 即"S中标签必须出现在行首"。
  - 失败语义（**2026-09-20 B3 起改为 fail-closed**）：非 200 / 解析不出 Safety / 超时 / 构造送检体
    失败时，插件**一律不放行**（请求/响应路径即时拒答，流式路径整流终止），并计入
    qwen3guard_failclosed_total。因此联调时若出现拒答，优先检查本替身是否返回合规格式、
    以及插件 timeout_ms 是否足够。

用法：
  python scripts/stub-qwen3guard.py --port 19100
  python scripts/stub-qwen3guard.py --port 19100 --unsafe-keywords 违法,暴力,制毒
"""
import argparse
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_UNSAFE = ["违法", "暴力", "制毒", "恐怖", "自杀", "jailbreak", "dan mode"]


class Handler(BaseHTTPRequestHandler):
    unsafe_keywords = DEFAULT_UNSAFE
    calls = 0

    def _send(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path.rstrip("/") in ("/healthz", "/"):
            self._send(200, {"status": "ok", "stub": "qwen3guard"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
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
        # 请求检测：插件只发一条 user；响应检测：user + assistant（取最后一条作为待检文本）
        content = messages[-1].get("content", "") if messages else ""
        # 响应检测时，把 user 提问也纳入关键词判断（更接近真实审核语义）
        prompt = " ".join(m.get("content", "") for m in messages[:-1]) if len(messages) > 1 else ""

        hit = [k for k in Handler.unsafe_keywords if k.lower() in (content + " " + prompt).lower()]
        if hit:
            verdict, categories, refusal = "Unsafe", ",".join(hit), "Yes"
        else:
            verdict, categories, refusal = "Safe", "", "No"

        Handler.calls += 1
        print("[stub-qwen3guard] call#%d model=%s verdict=%s hit=%s content=%r"
              % (Handler.calls, req.get("model"), verdict, hit, content[:60]), flush=True)

        # 判定文本按插件正则要求：Safety 位于行首
        text = "Safety: %s\nCategories: %s\nRefusal: %s" % (verdict, categories, refusal)
        self._send(200, {
            "id": "chatcmpl-stub-%d" % Handler.calls,
            "object": "chat.completion",
            "model": req.get("model") or "Qwen/Qwen3Guard-Gen-0.6B",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        })

    def log_message(self, fmt, *args):  # 静默默认访问日志（避免噪声）
        return


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=19100)
    ap.add_argument("--unsafe-keywords", default=",".join(DEFAULT_UNSAFE))
    args = ap.parse_args()
    Handler.unsafe_keywords = [k.strip() for k in args.unsafe_keywords.split(",") if k.strip()]
    srv = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print("[stub-qwen3guard] listening on 0.0.0.0:%d  unsafe_keywords=%s" % (args.port, Handler.unsafe_keywords), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("[stub-qwen3guard] stopped", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
