#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""chat-phala.py - 展示环境2.0 密态大模型客户端示例（零第三方依赖）

经 Higress 网关调用 Phala 云密态大模型（LLaMA-3.3-70B，TDX 密态）：
    client --明文--> Higress:8080 --(Wasm 信封)--> tee-infer --> Phala(TDX)

用法:
    python scripts/chat-phala.py "你的问题"
    python scripts/chat-phala.py --base http://<网关IP>:8080 "问题"

返回标准 OpenAI SSE（data: delta + finish_reason + [DONE]）。
503 = fail-closed（TEE 会话重建中，不降级明文）→ 自动重试最多 3 次。
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

MAX_RETRY = 3
RETRY_SLEEP = 2


def chat(base_url, messages, stream=True):
    """发送 text 载荷，消费 SSE 明文流，返回聚合全文。"""
    payload = json.dumps({
        "engine_type": "cmaas",
        "stream": stream,
        "messages": messages,
    }).encode("utf-8")
    url = base_url.rstrip("/") + "/v1/infer"

    for attempt in range(MAX_RETRY):
        req = urllib.request.Request(
            url, data=payload, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return _consume_sse(resp, stream)
        except urllib.error.HTTPError as he:
            if he.code == 503:
                print(f"[重试 {attempt + 1}/{MAX_RETRY}] "
                      f"TEE 会话重建中 (503, fail-closed)...", file=sys.stderr)
                time.sleep(RETRY_SLEEP)
                continue
            body = he.read().decode("utf-8", "replace")[:200]
            raise RuntimeError(f"请求失败 HTTP {he.code}: {body}")
        except Exception as e:  # noqa: BLE001 - 网络/超时统一按失败处理
            raise RuntimeError(f"请求失败: {e}") from e

    raise RuntimeError(f"多次 503 后仍失败（TEE 链路不可用）")


def _consume_sse(resp, stream):
    """逐行消费 OpenAI SSE，流式打印 delta，返回聚合明文。"""
    out = []
    for raw in resp:
        line = raw.decode("utf-8", "replace").strip()
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            break
        try:
            obj = json.loads(data)
        except json.JSONDecodeError:
            continue
        for choice in obj.get("choices", []):
            content = choice.get("delta", {}).get("content", "")
            if content:
                out.append(content)
                if stream:
                    print(content, end="", flush=True)
    if stream:
        print()
    return "".join(out)


def main():
    ap = argparse.ArgumentParser(
        description="密态大模型客户端（Higress 网关 → Phala TDX）")
    ap.add_argument("prompt", nargs="?", default="用一句话介绍机密计算")
    ap.add_argument("--base", default="http://127.0.0.1:8080",
                    help="Higress 网关地址（本机默认 127.0.0.1:8080）")
    args = ap.parse_args()

    # Windows 控制台中文输出兼容（GBK 控制台下按 UTF-8 输出）
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    print(f"[请求] 网关={args.base} 引擎=cmaas(Phala)")
    text = chat(args.base, [{"role": "user", "content": args.prompt}])
    print(f"\n[ok] 聚合明文长度={len(text)}")
    print(f"     全文: {text}")


if __name__ == "__main__":
    main()
