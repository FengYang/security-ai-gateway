#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
实验 1c：验证 int16 偶发崩坏根因，并验证修正方案

根因假设
--------
V[i] = (x_dom[i] + r[i]) mod R 为逐元素环绕(k_i∈{0,1})
    acc_v = Σ Wq·V = Σ Wq·(x_dom+r) − R·Σ(Wq·k_i)
    acc_r = Σ Wq·r
现有实现【先乘 scale 再取模】：
    val = float64(acc)*scale ⇒ 多出项 −R·scale·Σ(Wq·k_i)
    scale 非整数 ⇒ 该项 mod R 不归零 ⇒ 摧毁 1e6 域低位
修正实现【先整数域脱掩码，后乘 scale】：
    y = (acc_v − acc_r) mod R  (此时多出项为 R×整数，干净归零)
    result = signed(y) * scale / 1e6
"""
import numpy as np

MASK_MOD = 1 << 32
HALF_MOD = 1 << 31
INPUT_SCALE = 1e6

def quantize_matrix(W, bit_width):
    max_w = float(np.max(np.abs(W)))
    max_q = float((1 << (bit_width - 1)) - 1)
    scale = max_w / max_q
    return np.round(W / scale).astype(np.int32), scale

def to_mask_domain(x):
    return np.mod(np.trunc(np.asarray(x, dtype=np.float64) * INPUT_SCALE).astype(np.int64), MASK_MOD)

def run(dim, bit, seed, fixed):
    rng = np.random.default_rng(seed)
    W = rng.normal(0, 0.02, size=(dim, dim))
    x = rng.normal(0, 1.0, size=dim)
    Wq, scale = quantize_matrix(W, bit)
    x_dom = to_mask_domain(x)
    r = rng.integers(0, MASK_MOD, size=dim, dtype=np.uint64).astype(np.int64)
    V = np.mod(x_dom + r, MASK_MOD)
    acc_v = (Wq.astype(np.int64) * V[np.newaxis, :]).astype(np.int64).sum(axis=1)
    acc_r = (Wq.astype(np.int64) * r[np.newaxis, :]).astype(np.int64).sum(axis=1)
    if fixed:   # 修正：先整数域脱掩码，后乘 scale
        y = np.mod(acc_v - acc_r, MASK_MOD)
        s = np.where(y >= HALF_MOD, y - MASK_MOD, y).astype(np.float64)
        got = s * scale / INPUT_SCALE
    else:       # 现状：先乘 scale 再取模
        y_c = np.mod(np.trunc(acc_v.astype(np.float64) * scale).astype(np.int64), MASK_MOD)
        img = np.mod(np.trunc(acc_r.astype(np.float64) * scale).astype(np.int64), MASK_MOD)
        y = np.mod(y_c - img, MASK_MOD)
        got = np.where(y >= HALF_MOD, y - MASK_MOD, y).astype(np.float64) / INPUT_SCALE
    ref = W @ x
    return float(np.max(np.abs(got - ref)) / max(float(np.max(np.abs(ref))), 1e-12))

print("=" * 88)
print("实验 1c：根因验证 —— 现有实现 vs 修正实现（整数域先脱掩码）")
print("=" * 88)
print(f"{'bit':>5}{'dim':>7}{'现有 err/信号':>18}{'修正 err/信号':>18}{'结论':>16}")
for bit in (8, 16):
    for dim in (512, 1024, 2048, 3072, 4096, 6144):
        a = run(dim, bit, 11, fixed=False)
        b = run(dim, bit, 11, fixed=True)
        tag = "现崩->修正OK" if (a > 1e-2 and b < 1e-2) else ("两者OK" if a < 1e-2 else "两者崩")
        print(f"{bit:>5}{dim:>7}{a:>18.3e}{b:>18.3e}{tag:>16}")
print("\n注：err/信号 = max|got-ref| / max|ref|；>1e-2 视为崩坏")
print("=" * 88)
