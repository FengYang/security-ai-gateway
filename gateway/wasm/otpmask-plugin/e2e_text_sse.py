#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GF3.2 对齐改造端到端验证：
   - 对齐1：入站接受 OpenAI messages（统一 text 载荷契约 v1）；
   - 对齐2：出站重组为标准 OpenAI SSE（choices[].delta.content + finish_reason + [DONE]）；
   - fail-closed：未知消息角色拒绝。
   前置：docker compose -f docker-compose.yaml up -d --build（envoy 挂载本地重建 main.wasm）。
"""
import json
import sys

import requests

BASE = "http://127.0.0.1:10000"
TIMEOUT = 30


def post(payload: dict):
    try:
        r = requests.post(BASE + "/infer", json=payload, timeout=TIMEOUT)
        return r.status_code, r.text
    except requests.RequestException as e:
        return 0, f"network-error: {e}"


def check(name: str, status: int, body: str, must) -> bool:
    miss = [t for t in must if t not in body]
    if status == 0 or miss:
        print(f"[FAIL] {name}: status={status}, 缺={miss}")
        return False
    print(f"[PASS] {name}: status={status}")
    return True


def main() -> int:
    ok = True
    out = []

    # 对齐2：text 载荷 -> 标准 OpenAI SSE
    st, body = post({"text": "hello otp", "stream": True, "engine_type": "tee_gpu"})
    out.append((st, body))
    ok &= check("text 载荷标准SSE出站", st, body, [
        '"object":"chat.completion.chunk"', '"choices"', '"delta"', "data: [DONE]"])

    # 对齐1 + 对齐2：messages 入站闭环
    st2, body2 = post({"messages": [{"role": "system", "content": "sys"},
                                    {"role": "user", "content": "hi otp"}]})
    out.append((st2, body2))
    ok &= check("messages 入站标准SSE出站", st2, body2, [
        '"choices"', '"delta"', "data: [DONE]"])

    # fail-closed：未知角色
    st3, body3 = post({"messages": [{"role": "tool", "content": "x"}]})
    closed = st3 in (400, 403)
    out.append((st3, body3))
    if closed:
        print("[PASS] 未知角色 fail-closed")
    else:
        ok = False
        print(f"[FAIL] 未知角色未关断: status={st3}, body={body3[:200]}")

    print("=" * 40)
    for i, (st, b) in enumerate(out):
        print(f"[req{i}] status={st} body_prefix={b[:120]!r}")
    print("=" * 40)
    print(f"[{'PASS' if ok else 'FAIL'}-VERDICT] 对齐1/对齐2 端到端")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())