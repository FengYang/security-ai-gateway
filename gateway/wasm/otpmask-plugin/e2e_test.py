"""端到端加解密闭环验证脚本（M3 适配版）。

流程：
  1. 发送明文请求 {"vectors": [[100,200,300],[42,43,44]]} 经网关（:10000）
  2. mock-infer 在密文域执行 +DELTA 同态运算
  3. 断言网关响应为 (明文 + DELTA) mod R（解密还原 + 同态结果）
"""
import json
import sys
import urllib.request

GATEWAY = "http://127.0.0.1:10000/infer"
DELTA = 7  # 与 mock_infer.py 的 MOCK_DELTA 对齐

PLAIN = {"vectors": [[100, 200, 300], [42, 43, 44]]}


def post(url: str, payload: dict) -> str:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode()


def main() -> int:
    print("== M3 加解密闭环验证（密文域同态 DELTA=%d）==" % DELTA)
    raw = post(GATEWAY, PLAIN)
    out = json.loads(raw)
    print(f"[1] 网关响应: {raw}")

    want = [(x + DELTA) % (1 << 32) for x in PLAIN["vectors"][0]]
    if out.get("output") != want:
        print(f"[FAIL] 解密结果 {out.get('output')} != 预期 {want}")
        return 1
    print(f"[2] PASS 密文域同态结果 = 明文+DELTA = {want}")
    print("[3] 请人工核对 mock-infer 日志中的密文向量（应与明文不同）")
    return 0


if __name__ == "__main__":
    sys.exit(main)
