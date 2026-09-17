#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OG-13 L2 语义分类器侧车 stub（浸泡 harness 用）。

HTTP POST /  :  {"text": "..."} -> {"blocked": bool, "category": "...", "confidence": 0.xx, "match": "..."}

可配置：
  - 延迟分布：对数正态，由 median_ms / p99_ms 校准
  - 命中率 hit_rate：blocked=true 的比例
  - 命中类目分布 categories：按权重抽样
  - 不可用率 unavailable_rate：模拟服务不可用（连接挂住 / 非 200 / 坏响应）
  - 失败细分：unreachable / bad_status / bad_response 按比例

与 OG-0b 参数对齐：
  CPU 形态：median=2800ms  p99=4500ms
  GPU 形态：median=200ms   p99=500ms
"""

import argparse
import json
import math
import random
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler, ThreadingHTTPServer


# ---------- 对数正态：由 median / p99 反解 mu / sigma ----------
def fit_lognormal(median: float, p99: float) -> tuple[float, float]:
    """
    已知对数正态的 median 与 P99，反算 mu 和 sigma。
      median = exp(mu)            => mu = ln(median)
      P99    = exp(mu + 2.326*sigma) => sigma = (ln(P99) - mu) / 2.326
    """
    if median <= 0 or p99 <= 0 or p99 <= median:
        raise ValueError(f"median={median} p99={p99} 非法（须 p99 > median > 0）")
    mu = math.log(median)
    sigma = (math.log(p99) - mu) / 2.3263478740408408  # z_{0.99}
    return mu, sigma


def sample_lognormal(rng: random.Random, mu: float, sigma: float) -> float:
    return math.exp(rng.gauss(mu, sigma))


# ---------- 类目抽样 ----------
def parse_categories(spec: str) -> list[tuple[str, float]]:
    """
    解析 --categories  参数：
      "A1-07:0.3,A2-03:0.4,A4-02:0.3"
    返回 [(cat, weight), ...]，权重已归一。
    """
    if not spec.strip():
        return [("A2-03", 1.0)]
    items = []
    total = 0.0
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            cat, w = part.rsplit(":", 1)
            w = float(w)
        else:
            cat, w = part, 1.0
        items.append((cat, w))
        total += w
    if total == 0:
        raise ValueError("categories 权重和为 0")
    return [(cat, w / total) for cat, w in items]


def sample_category(rng: random.Random, cats: list[tuple[str, float]]) -> str:
    r = rng.random()
    acc = 0.0
    for cat, w in cats:
        acc += w
        if r <= acc:
            return cat
    return cats[-1][0]


# ---------- 全局配置（由 main 填充，handler 读取） ----------
class _G:
    mu = 0.0
    sigma = 0.0
    hit_rate = 0.1
    categories = [("A2-03", 1.0)]
    unavailable_rate = 0.0
    # 不可用细分（归一后比例）
    unreachable_ratio = 0.5   # 连接挂住（超时）
    bad_status_ratio = 0.3    # HTTP != 200
    bad_response_ratio = 0.2  # HTTP 200 但 JSON 畸形
    rng: random.Random = random.Random()
    rng_lock: threading.Lock = threading.Lock()


g = _G()


# ---------- HTTP handler ----------
class L2Handler(BaseHTTPRequestHandler):
    # 抑制默认 stderr 日志（浸泡跑起来更干净）
    def log_message(self, format, *args):
        pass

    def do_POST(self):
        # 1. 预生成所有随机数（锁内完成，线程安全）
        with g.rng_lock:
            fail_r = g.rng.random()
            is_unavailable = fail_r < g.unavailable_rate
            if is_unavailable:
                sub = fail_r / max(g.unavailable_rate, 1e-12)
                if sub < g.unreachable_ratio:
                    fail_kind = "unreachable"
                elif sub < g.unreachable_ratio + g.bad_status_ratio:
                    fail_kind = "bad_status"
                else:
                    fail_kind = "bad_response"
            else:
                fail_kind = ""
            delay_ms = sample_lognormal(g.rng, g.mu, g.sigma)
            if delay_ms < 1.0:
                delay_ms = 1.0
            is_hit = g.rng.random() < g.hit_rate
            if is_hit:
                cat = sample_category(g.rng, g.categories)
                conf = g.rng.uniform(0.7, 0.99)
            else:
                cat = ""
                conf = 0.0

        # 2. 读 body（锁外，I/O）
        length = int(self.headers.get("Content-Length", "0"))
        if length > 0:
            self.rfile.read(length)

        # 3. 不可用分支（锁外）
        if is_unavailable:
            if fail_kind == "unreachable":
                time.sleep(20.0)
                return
            elif fail_kind == "bad_status":
                self.send_response(500)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"internal error")
                return
            else:  # bad_response
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b"{broken json")
                return

        # 4. 延迟（锁外，sleep 不占锁）
        time.sleep(delay_ms / 1000.0)

        # 5. 回响应（锁外，I/O）
        if is_hit:
            resp = {
                "blocked": True,
                "category": cat,
                "confidence": round(conf, 4),
                "match": f"stub-match-{cat}",
            }
        else:
            resp = {"blocked": False}

        body = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # /healthz 健康检查
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        self.send_response(404)
        self.end_headers()


def main():
    p = argparse.ArgumentParser(description="OG-13 L2 classifier stub (soak harness)")
    p.add_argument("--port", type=int, default=19099, help="监听端口 (default: 19099)")
    p.add_argument("--median-ms", type=float, default=2800.0,
                   help="L2 单句延迟中位数 ms (default: 2800 = CPU 形态)")
    p.add_argument("--p99-ms", type=float, default=4500.0,
                   help="L2 单句延迟 P99 ms (default: 4500 = CPU 形态)")
    p.add_argument("--hit-rate", type=float, default=0.05,
                   help="命中率 blocked=true 比例 (default: 0.05)")
    p.add_argument("--categories", type=str, default="A1-07:0.3,A2-03:0.4,A4-02:0.3",
                   help="命中类目及权重，格式 cat:w,cat:w (default: A1-07:0.3,A2-03:0.4,A4-02:0.3)")
    p.add_argument("--unavailable-rate", type=float, default=0.0,
                   help="不可用率：unreachable+bad_status+bad_response 总和 (default: 0.0)")
    p.add_argument("--seed", type=int, default=20260917,
                   help="随机种子 (default: 20260917)")
    p.add_argument("--profile", choices=["cpu", "gpu", "custom"], default="custom",
                   help="快捷形态：cpu(2800/4500) / gpu(200/500) / custom 用参数值")
    args = p.parse_args()

    # profile 快捷方式覆盖延迟参数
    if args.profile == "cpu":
        median_ms, p99_ms = 2800.0, 4500.0
    elif args.profile == "gpu":
        median_ms, p99_ms = 200.0, 500.0
    else:
        median_ms, p99_ms = args.median_ms, args.p99_ms

    g.rng = random.Random(args.seed)
    g.mu, g.sigma = fit_lognormal(median_ms, p99_ms)
    g.hit_rate = max(0.0, min(1.0, args.hit_rate))
    g.categories = parse_categories(args.categories)
    g.unavailable_rate = max(0.0, min(1.0, args.unavailable_rate))

    # 不可用细分保持默认 0.5 / 0.3 / 0.2
    s = g.unreachable_ratio + g.bad_status_ratio + g.bad_response_ratio
    g.unreachable_ratio /= s
    g.bad_status_ratio /= s
    g.bad_response_ratio /= s

    print(f"[og13-l2-stub] port={args.port} profile={args.profile} "
          f"median_ms={median_ms:.0f} p99_ms={p99_ms:.0f} "
          f"hit_rate={g.hit_rate:.3f} unavailable_rate={g.unavailable_rate:.3f} "
          f"seed={args.seed}", flush=True)
    print(f"[og13-l2-stub] lognormal mu={g.mu:.4f} sigma={g.sigma:.4f}", flush=True)
    print(f"[og13-l2-stub] categories={g.categories}", flush=True)

    server = ThreadingHTTPServer(("127.0.0.1", args.port), L2Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[og13-l2-stub] exiting", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
