"""全链路正确性回归测试（M3-2）。

用例覆盖：
  C1 多向量：[[100,200,300],[42,43,44]] → output = vectors[0] + DELTA
  C2 随机值：R 内随机向量
  C3 边界值：0 与 R/2-1（避免 x+DELTA 回绕）
  C4 维度：1 / 8 / 16
  C5 大向量数：100 个向量（路由与聚合正确性）
断言：output == (vectors[0] + DELTA) mod R
"""
import json
import random
import sys
import urllib.request

GATEWAY = "http://127.0.0.1:10000/infer"
R = 1 << 32
DELTA = 7

CASES = {
    "C1_多向量": {"vectors": [[100, 200, 300], [42, 43, 44]]},
    "C2_随机值": {"vectors": [[random.randrange(0, R // 2) for _ in range(4)]]},
    "C3_边界值": {"vectors": [[0, R // 2 - 1], [R // 2 - 2, 0]]},
    "C4_dim1": {"vectors": [[5]]},
    "C4_dim8": {"vectors": [[i * 100 for i in range(8)]]},
    "C4_dim16": {"vectors": [[i * 37 % 1000 for i in range(16)]]},
    "C5_百向量": {"vectors": [[random.randrange(0, R // 2) for _ in range(3)] for _ in range(100)]},
}


def post(payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        GATEWAY, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def main() -> int:
    print("== M3 全链路正确性回归 ==")
    fails = 0
    for name, payload in CASES.items:
        try:
            out = post(payload)
            got = out.get("output")
            want = [(x + DELTA) % R for x in payload["vectors"][0]]
            ok = got == want
            status = "PASS" if ok else "FAIL"
            print(f"[{name}] vectors={len(payload['vectors'])} dim={len(payload['vectors'][0])} -> {status}")
            if not ok:
                print(f"   got={got} want={want}")
                fails += 1
        except Exception as e:
            print(f"[{name}] ERROR: {e}")
            fails += 1
    print(f"\n结果: {len(CASES) - fails}/{len(CASES)} 通过")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main)
