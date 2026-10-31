#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""实验 2b：仅验证 R=2**64（int128 累加）方案在 S=1e6 下是否零溢出 + 余量比例。"""
import numpy as np

R64 = 1 << 64
R64_HALF = 1 << 63
R32 = 1 << 32


def quantize(W, bit):
    max_w = float(np.max(np.abs(W)))
    max_q = float((1 << (bit - 1)) - 1)
    scale = max_w / max_q
    return np.round(W / scale).astype(np.int32), scale


def fixed_unmask_64(Wq, scale, x_signed, S, r, dim):
    rL = [int(v) for v in r.tolist()]
    xL = [int(v) for v in x_signed.tolist()]
    V = [(((v % R64) + rr) % R64) for v, rr in zip(xL, rL)]
    got = np.zeros(dim, dtype=np.float64)
    T_max = 0
    for i in range(dim):
        Wi = Wq[i].tolist()          # 仅本行常驻内存，避免 67M 个 Python int 同时存在
        acc_v = 0
        acc_r = 0
        Ti = 0
        for j in range(dim):
            w = Wi[j]
            acc_v += w * V[j]
            acc_r += w * rL[j]
            Ti += w * xL[j]
        y = (acc_v - acc_r) % R64
        yv = y - R64 if y >= R64_HALF else y
        got[i] = yv * scale / S
        if abs(Ti) > T_max:
            T_max = abs(Ti)
    return T_max, got


print("### Part B: R=2**64, S=1e6, 验证零溢出与余量 ###")
print(f"{'bit':>5}{'dim':>7}{'overflow%':>12}{'max|T|/R/2':>14}{'结论':>10}")
SEEDS = 6
for bit in (8, 16):
    for dim in (512, 1024, 2048, 4096, 6144, 8192):
        rng0 = np.random.default_rng(20261031)
        W = rng0.normal(0, 0.02, size=(dim, dim))
        Wq, scale = quantize(W, bit)
        overflow = 0
        ratio_max = 0.0
        for seed in range(SEEDS):
            rng = np.random.default_rng(seed * 1000 + 7)
            x = rng.normal(0, 1.0, size=dim)
            x_signed = np.trunc(x * 1e6).astype(np.int64)
            r = rng.integers(0, 1 << 63, size=dim, dtype=np.int64)
            T_max, got = fixed_unmask_64(Wq, scale, x_signed, 1e6, r, dim)
            if T_max >= R64_HALF:
                overflow += 1
            ratio_max = max(ratio_max, T_max / R64_HALF)
        tag = "SAFE" if overflow == 0 else "BROKEN"
        print(f"{bit:>5}{dim:>7}{overflow*100:>11.1f}%{ratio_max:>14.3e}{tag:>10}")
print("\n结论：max|T|/R/2 越小余量越大。若均 <<1 则 R=2**64 保留 S=1e6 即安全且无视 dim 上限。")
