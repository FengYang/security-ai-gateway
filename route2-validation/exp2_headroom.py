#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
实验 2：R/S 决策空间扫描 —— 修正方案（整数域先脱掩码）的安全边界

背景
----
路线 2 掩码像推理当前实现存在两处数值缺陷：
  (1)【脆弱抵消】CipherLinear/MaskImage 先乘 scale 再取模，导致 mod R 无法干净归零，
      偶发崩坏（实验 1c 已验证，int16/dim>=3072 误差达信号的 73~132 倍）。
  (2)【模域余量】即便改为“整数域先脱掩码”，脱掩后的真值累加器 T = Σ Wq·x_dom 仍须满足
       |T| < R/2，否则 mod(T, R) 直接丢弃信息 → 静默崩坏。

本实验目标：把 M0/M1（定 R 与 S）从“拍脑袋”变为“数据驱动”。
扫描维度：
  R  ∈ {2**32, 2**64}            掩码模（2**64 代表 int128 累加方案）
  S  ∈ {1e6, 1e4, 1e3}           输入定点缩放
  bit∈ {8, 16}                   权重量化位宽
  dim∈ {512,1024,2048,3072,4096,6144,8192}
指标：
  overflow_rate  该配置下 max|T| >= R/2 的 trial 比例（=静默崩坏概率）
  max_err_ratio 范围内 trial 的最大 err/信号
  input_q_err   仅由输入定点化引入的相对误差（降 S 的精度代价）
结论：overflow_rate==0 且 max_err_ratio<1e-2 才算 SAFE。

注意：R=2**64 路径累加器超 int64，用 Python int 精确累加（仅中小 dim + 少 seed 控时）。
"""
import numpy as np

R32 = 1 << 32
R32_HALF = 1 << 31
R64 = 1 << 64
R64_HALF = 1 << 63


def quantize(W, bit):
    max_w = float(np.max(np.abs(W)))
    max_q = float((1 << (bit - 1)) - 1)
    scale = max_w / max_q
    return np.round(W / scale).astype(np.int32), scale


def fixed_unmask_32(Wq, scale, x_signed, S, r, dim):
    """R=2**32 路径：numpy int64 精确（累加器不超 int64）。"""
    x_dom = np.mod(x_signed, R32).astype(np.int64)          # 无符号表示
    V = np.mod(x_dom + r, R32).astype(np.int64)             # 发往不可信方的掩码输入
    acc_v = (Wq.astype(np.int64) * V).sum(axis=1)
    acc_r = (Wq.astype(np.int64) * r).sum(axis=1)
    y = np.mod(acc_v - acc_r, R32)
    s = np.where(y >= R32_HALF, y - R32, y).astype(np.float64)
    got = s * scale / S
    T = (Wq.astype(np.int64) * x_signed).sum(axis=1)        # 真值累加器（有符号，未取模）
    return T, got


def fixed_unmask_64(Wq, scale, x_signed, S, r, dim):
    """R=2**64 路径：Python int 精确累加（Wq*V 可达 ~2**79，超 int64）。"""
    x_dom = [v % R64 for v in x_signed.tolist()]
    V = [(xd + rr) % R64 for xd, rr in zip(x_dom, r.tolist())]
    WqL = Wq.astype(np.int64).tolist()
    got = np.zeros(dim, dtype=np.float64)
    T_max = 0
    for i in range(dim):
        acc_v = 0
        acc_r = 0
        Ti = 0
        for j in range(dim):
            acc_v += WqL[i * dim + j] * V[j]
            acc_r += WqL[i * dim + j] * r[j]
            Ti += WqL[i * dim + j] * x_signed[j]
        y = (acc_v - acc_r) % R64
        yv = y - R64 if y >= R64_HALF else y
        got[i] = yv * scale / S
        if abs(Ti) > T_max:
            T_max = abs(Ti)
    return T_max, got


def run_cfg(R, S, bit, dim, n_seed):
    rng0 = np.random.default_rng(20261031)
    W = rng0.normal(0, 0.02, size=(dim, dim))
    Wq, scale = quantize(W, bit)
    overflow = 0
    max_err_list = []
    input_q_err_list = []
    for seed in range(n_seed):
        rng = np.random.default_rng(seed * 1000 + 7)
        x = rng.normal(0, 1.0, size=dim)
        x_signed = np.trunc(x * S).astype(np.int64)
        # 输入定点化误差（降 S 的精度代价，与 R 无关）
        xq = x_signed / S
        ref_full = W @ x
        ref_q = W @ xq
        input_q_err = float(np.max(np.abs(ref_q - ref_full)) /
                            max(float(np.max(np.abs(ref_full))), 1e-12))
        input_q_err_list.append(input_q_err)
        r_high = R if R <= R32 else (1 << 63)   # 2**64 超出 int64，r 范围不影响溢出指标
        r = rng.integers(0, r_high, size=dim, dtype=np.int64)
        if R == R32:
            T, got = fixed_unmask_32(Wq, scale, x_signed, S, r, dim)
            T_max = int(np.max(np.abs(T)))
            ref = ref_full
            err = float(np.max(np.abs(got - ref)) /
                        max(float(np.max(np.abs(ref))), 1e-12))
        else:
            T_max, got = fixed_unmask_64(Wq, scale, x_signed, S, r, dim)
            ref = ref_full
            err = float(np.max(np.abs(got - ref)) /
                        max(float(np.max(np.abs(ref))), 1e-12))
        if T_max >= (R32_HALF if R == R32 else R64_HALF):
            overflow += 1
        else:
            max_err_list.append(err)
    rate = overflow / n_seed
    worst_err = max(max_err_list) if max_err_list else float('inf')
    avg_inq = float(np.mean(input_q_err_list))
    return rate, worst_err, avg_inq


print("=" * 110)
print("实验 2：R/S 决策空间扫描（修正方案 = 整数域先脱掩码）。指标：overflow_rate=静默崩坏概率")
print("=" * 110)

# ---- Part A: R=2**32 ----
print("\n### Part A: R = 2**32（现状模长），扫描 S 与 bit × dim ###")
print(f"{'S':>8}{'bit':>5}{'dim':>7}{'overflow%':>12}{'max_err/信号':>16}{'输入量化err':>14}{'结论':>10}")
SEEDS_A = 12
for S in (1e6, 1e4, 1e3):
    for bit in (8, 16):
        for dim in (512, 1024, 2048, 3072, 4096, 6144, 8192):
            rate, worst, inq = run_cfg(R32, S, bit, dim, SEEDS_A)
            safe = (rate == 0 and worst < 1e-2)
            tag = "SAFE" if safe else ("BROKEN" if rate > 0 else "边界")
            print(f"{S:>8.0f}{bit:>5}{dim:>7}{rate*100:>11.1f}%{worst:>16.3e}{inq:>14.3e}{tag:>10}")

# ---- Part B: R=2**64 proof (only small/mid dim + few seeds, Python-int) ----
print("\n### Part B: R = 2**64（int128 累加方案），S=1e6，验证零溢出 ###")
print(f"{'S':>8}{'bit':>5}{'dim':>7}{'overflow%':>12}{'max|T|/R/2':>14}{'结论':>10}")
SEEDS_B = 5
for bit in (8, 16):
    for dim in (512, 1024, 2048, 4096):
        rate, worst, inq = run_cfg(R64, 1e6, bit, dim, SEEDS_B)
        # 重新取一次 T_max/R/2 比例
        rng0 = np.random.default_rng(20261031)
        W = rng0.normal(0, 0.02, size=(dim, dim))
        Wq, scale = quantize(W, bit)
        ratio_max = 0.0
        for seed in range(SEEDS_B):
            rng = np.random.default_rng(seed * 1000 + 7)
            x = rng.normal(0, 1.0, size=dim)
            x_signed = np.trunc(x * 1e6).astype(np.int64)
            r = rng.integers(0, 1 << 63, size=dim, dtype=np.int64)
            T_max, _ = fixed_unmask_64(Wq, scale, x_signed, 1e6, r, dim)
            ratio = T_max / R64_HALF
            ratio_max = max(ratio_max, ratio)
        tag = "SAFE" if rate == 0 else "BROKEN"
        print(f"{1e6:>8.0f}{bit:>5}{dim:>7}{rate*100:>11.1f}%{ratio_max:>14.3e}{tag:>10}")

# ---- Part C: 输入定点化误差随 S 的变化（降 S 的精度代价）----
print("\n### Part C: 输入定点化相对误差（仅由 S 决定，与 R 无关）###")
print(f"{'S':>8}{'平均输入量化err':>18}{'结论':>14}")
for S in (1e6, 1e4, 1e3):
    _, _, inq = run_cfg(R32, S, 8, 2048, SEEDS_A)
    tag = "精度OK" if inq < 1e-2 else "精度受损"
    print(f"{S:>8.0f}{inq:>18.3e}{tag:>14}")

print("\n" + "=" * 110)
print("结论速读：R=2**32 必须降 S 到 ~1e3~1e4 才 SAFE（牺牲输入动态范围）；")
print("         R=2**64 保留 S=1e6 即 SAFE（需内核 int128 累加）。二者择一即解锁 M0/M1。")
print("=" * 110)
