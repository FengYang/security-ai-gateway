"""Wasm body 承载能力 PoC（M2-5）：MB 级 body 经网关加解密的处理能力实测。

用例：
  - 64KB / 256KB / 1MB 明文向量请求
  - 测量：客户端到客户端总延迟（含加解密 + mock 转发 + 网络）
  - 断言：解密还原正确
输出：JSON 结果供记录到兼容性报告。
"""
import json
import time
import urllib.request
import sys

GATEWAY = "http://127.0.0.1:10000/infer"

SIZES = {
    "64KB": 64 * 1024,
    "256KB": 256 * 1024,
    "1MB": 1024 * 1024,
}


def post(url: str, payload: dict) -> str:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode()


def make_vectors(total_bytes: int, dim: int = 8) -> list:
    # 每个元素 ~10 字符（含逗号空格），估算向量数
    per_vec = sum(len(str(x)) + 2 for x in [0] * dim)
    n = max(1, total_bytes // per_vec)
    vecs = []
    for _ in range(n):
        vecs.append([i % 1000 for i in range(dim)])
    return vecs


def main() -> int:
    print("== M2-5 Wasm body 承载能力 PoC ==")
    results = {}
    for name, size in SIZES.items:
        vecs = make_vectors(size)
        payload = {"vectors": vecs}
        t0 = time.perf_counter
        try:
            raw = post(GATEWAY, payload)
            dt_ms = (time.perf_counter - t0) * 1000
            out = json.loads(raw)
            ok = out.get("output") == vecs[0]
            results[name] = {"ok": ok, "latency_ms": round(dt_ms, 1), "vectors": len(vecs)}
            print(f"[{name}] 输入 {len(vecs)} 向量 延迟 {dt_ms:.1f}ms 还原{'PASS' if ok else 'FAIL'}")
        except Exception as e:
            results[name] = {"ok": False, "error": str(e)}
            print(f"[{name}] 失败: {e}")
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0 if all(r.get("ok") for r in results.values) else 1


if __name__ == "__main__":
    sys.exit(main)
