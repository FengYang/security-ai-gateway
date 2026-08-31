"""基线性能测试（M3-3）：区分网关增量延迟与端到端延迟。

方法：
  路径 A（直连 mock-infer:19000）：发送密文格式 payload → 测 mock 处理基线
  路径 B（经网关:10000）：发送明文格式 payload → 测全链路（加密→mock→解密）
  网关增量延迟 ≈ P99(B) - P99(A)（mock 处理开销相同，差值即网关+插件开销）

采样 N=100，输出 P50/P99/均值。
"""
import json
import statistics
import sys
import time
import urllib.request

GATEWAY = "http://127.0.0.1:10000/infer"
MOCK = "http://127.0.0.1:19000/infer"
N = 100


def post(url: str, payload: dict) -> bytes:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def bench(url: str, payload: dict, n: int) -> list:
    # 预热
    try:
        post(url, payload)
    except Exception:
        pass
    samples = []
    for _ in range(n):
        t0 = time.perf_counter
        post(url, payload)
        samples.append((time.perf_counter - t0) * 1000)
    return samples


def pct(samples: list, p: float) -> float:
    s = sorted(samples)
    idx = min(len(s) - 1, int(len(s) * p))
    return s[idx]


def report(name: str, samples: list) -> dict:
    return {
        "path": name,
        "p50_ms": round(pct(samples, 0.5), 2),
        "p99_ms": round(pct(samples, 0.99), 2),
        "mean_ms": round(statistics.mean(samples), 2),
    }


def main() -> int:
    print(f"== M3-3 性能基线（N={N}）==")

    # 小 payload：dim=8 单向量
    small_plain = {"vectors": [[i * 100 for i in range(8)]]}
    small_cipher = {"cipher_vectors": [[i * 1000003 % (1 << 32) for i in range(8)]], "nonce": "a" * 32, "model": "mock"}

    a_small = bench(MOCK, small_cipher, N)
    b_small = bench(GATEWAY, small_plain, N)
    r_a = report("直连mock(dim8)", a_small)
    r_b = report("经网关(dim8)", b_small)
    print(json.dumps(r_a, ensure_ascii=False))
    print(json.dumps(r_b, ensure_ascii=False))
    print(f"网关增量延迟(dim8): P99 {r_b['p99_ms'] - r_a['p99_ms']:.2f}ms | 均值 {r_b['mean_ms'] - r_a['mean_ms']:.2f}ms")

    # 大 payload：256KB
    vecs = [[i % 1000 for i in range(8)] for _ in range(10922)]
    big_plain = {"vectors": vecs}
    big_cipher = {"cipher_vectors": vecs, "nonce": "a" * 32, "model": "mock"}
    a_big = bench(MOCK, big_cipher, 30)
    b_big = bench(GATEWAY, big_plain, 30)
    r_a_big = report("直连mock(256KB)", a_big)
    r_b_big = report("经网关(256KB)", b_big)
    print(json.dumps(r_a_big, ensure_ascii=False))
    print(json.dumps(r_b_big, ensure_ascii=False))
    print(f"网关增量延迟(256KB): P99 {r_b_big['p99_ms'] - r_a_big['p99_ms']:.2f}ms | 均值 {r_b_big['mean_ms'] - r_a_big['mean_ms']:.2f}ms")
    return 0


if __name__ == "__main__":
    sys.exit(main)
