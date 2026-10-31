#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
实验 1b：定位 int16@大 dim 崩坏根因 + 修正 E1.2 环绕判据

诊断内容
--------
D1 对 int16 做 dim 扫描（1024..4096），打印中间量：
     max|acc| 是否越过 2^53(float64 整数精确表示上限) / 2^63(int64)
     max|val| 与 ULP(val)     —— 浮点 resolution 是否吞掉 1e6 域信号
     max|recovered| vs max|ref| —— 是否整体崩坏
D2 验证假设：float64 在 acc 量级上相对精度 => val 的绝对分辨率
     若 ULP(val) 与关心的信号量级( result*1e6 )可比，则 working precision 不足

E1.2' 修正判据：改用 误差 / max|ref|（按输出量级归一化，非逐元素），
     环绕时该比值会突跳；量化误差时该比值随 dim/位数平滑。
"""

import numpy as np

MASK_MOD = 1 << 32
HALF_MOD = 1 << 31
INPUT_SCALE = 1e6
U53 = 1 << 53          # float64 整数精确表示上限
U63 = 1 << 63


def quantize_matrix(W, bit_width):
    max_w = float(np.max(np.abs(W)))
    max_q = float((1 << (bit_width - 1)) - 1)
    scale = max_w / max_q
    return np.round(W / scale).astype(np.int32), scale


def to_mask_domain(x):
    return np.mod(np.trunc(np.asarray(x, dtype=np.float64) * INPUT_SCALE).astype(np.int64), MASK_MOD)


def run_diag(dim, bit, seed=11):
    rng = np.random.default_rng(seed)
    W = rng.normal(0, 0.02, size=(dim, dim))
    x = rng.normal(0, 1.0, size=dim)

    Wq, scale = quantize_matrix(W, bit)
    x_dom = to_mask_domain(x)
    r = rng.integers(0, MASK_MOD, size=dim, dtype=np.uint64).astype(np.int64)
    V = np.mod(x_dom + r, MASK_MOD)

    acc_v = (Wq.astype(np.int64) * V[np.newaxis, :]).astype(np.int64).sum(axis=1)
    acc_r = (Wq.astype(np.int64) * r[np.newaxis, :]).astype(np.int64).sum(axis=1)

    val_v = acc_v.astype(np.float64) * scale
    val_r = acc_r.astype(np.float64) * scale

    y_c = np.mod(np.trunc(val_v).astype(np.int64), MASK_MOD)
    img = np.mod(np.trunc(val_r).astype(np.int64), MASK_MOD)
    y = np.mod(y_c - img, MASK_MOD)
    signed = np.where(y >= HALF_MOD, y - MASK_MOD, y)
    got = signed.astype(np.float64) / INPUT_SCALE
    ref = W @ x

    max_acc = int(np.max(np.maximum(np.abs(acc_v), np.abs(acc_r))))
    # val 的浮点分辨率（ULP）：2^(e-52)，e = floor(log2(max|val|))
    mv = float(np.max(np.abs(val_v)))
    e = int(np.floor(np.log2(mv))) if mv > 0 else 0
    ulp = 2.0 ** (e - 52)
    err_norm = float(np.max(np.abs(got - ref)) / max(float(np.max(np.abs(ref))), 1e-12))
    return {
        "dim": dim, "bit": bit, "max_acc": max_acc, "acc_gt_2pow53": max_acc > U53,
        "acc_gt_2pow63": max_acc > U63, "max_val": mv, "ulp_val": ulp,
        "signal_scale": float(np.max(np.abs(ref))) * INPUT_SCALE,
        "max_ref": float(np.max(np.abs(ref))), "max_got": float(np.max(np.abs(got))),
        "err_over_maxref": err_norm,
    }


def main():
    print("=" * 100)
    print("实验 1b：int16 崩坏根因诊断")
    print("=" * 100)
    print("关键量解释：")
    print("  max_acc        : int64 累加器实际最大绝对值")
    print("  >2^53?         : 越过则 float64 无法精确表示该整数 -> 低位被吞")
    print("  max_val/ulp_val: val=acc*scale 的量级与其浮点分辨率(ULP)")
    print("  signal_scale   : 关心的信号量级 = |result|*1e6（约 1e6 量级）")
    print("  ulp vs signal  : 若 ulp_val 接近/超过 1，则 1e6 域整数精度被破坏")
    print("  err/max|ref|   : 按输出量级归一化的误差（环绕/崩坏时突跳）")

    print("\n[D1] int16 dim 扫描")
    hdr = (f"{'dim':>6}{'max_acc':>16}{'>2^53':>8}{'max_val':>14}{'ulp_val':>12}"
           f"{'signal*1e6':>14}{'max_ref':>10}{'max_got':>10}{'err/max|ref|':>14}")
    print(hdr)
    for dim in (512, 1024, 2048, 3072, 4096, 6144):
        d = run_diag(dim, 16)
        print(f"{d['dim']:>6}{d['max_acc']:>16.3e}{str(d['acc_gt_2pow53']):>8}"
              f"{d['max_val']:>14.3e}{d['ulp_val']:>12.3e}{d['signal_scale']:>14.3e}"
              f"{d['max_ref']:>10.3e}{d['max_got']:>10.3e}{d['err_over_maxref']:>14.3e}")

    print("\n[D2] int8 对照（应显著更健壮）")
    print(hdr)
    for dim in (2048, 4096):
        d = run_diag(dim, 8)
        print(f"{d['dim']:>6}{d['max_acc']:>16.3e}{str(d['acc_gt_2pow53']):>8}"
              f"{d['max_val']:>14.3e}{d['ulp_val']:>12.3e}{d['signal_scale']:>14.3e}"
              f"{d['max_ref']:>10.3e}{d['max_got']:>10.3e}{d['err_over_maxref']:>14.3e}")

    print("\n" + "=" * 100)
    print("[E1.2'] 修正判据后的环绕边界扫描（int8, dim=1024，误差按输出量级归一化）")
    print("        理论硬边界：|result| < 2^31/1e6 = 2147.483648")
    rng = np.random.default_rng(20261031)
    dim = 1024
    x = rng.normal(0, 1.0, size=dim)
    W0 = rng.normal(0, 0.02, size=(dim, dim))
    base_max = float(np.max(np.abs(W0 @ x)))
    print(f"\n{'目标|y|':>12}{'实测max|y|':>16}{'maxAbsErr':>14}{'err/max|ref|':>14}{'判定':>12}")
    for target in (1.0, 10.0, 100.0, 1000.0, 2000.0, 2140.0, 2147.0, 2150.0, 2200.0, 5000.0):
        W = W0 * (target / base_max)
        Wq, scale = quantize_matrix(W, 8)
        x_dom = to_mask_domain(x)
        rr = np.random.default_rng(7)
        r = rr.integers(0, MASK_MOD, size=dim, dtype=np.uint64).astype(np.int64)
        V = np.mod(x_dom + r, MASK_MOD)
        acc_v = (Wq.astype(np.int64) * V[np.newaxis, :]).astype(np.int64).sum(axis=1)
        acc_r = (Wq.astype(np.int64) * r[np.newaxis, :]).astype(np.int64).sum(axis=1)
        y_c = np.mod(np.trunc(acc_v.astype(np.float64) * scale).astype(np.int64), MASK_MOD)
        img = np.mod(np.trunc(acc_r.astype(np.float64) * scale).astype(np.int64), MASK_MOD)
        y = np.mod(y_c - img, MASK_MOD)
        got = np.where(y >= HALF_MOD, y - MASK_MOD, y).astype(np.float64) / INPUT_SCALE
        ref = W @ x
        mabs = float(np.max(np.abs(got - ref)))
        denom = max(float(np.max(np.abs(ref))), 1e-12)
        ratio = mabs / denom
        print(f"{target:>12.1f}{float(np.max(np.abs(ref))):>16.3e}{mabs:>14.3e}"
              f"{ratio:>14.3e}{'OK' if ratio < 0.05 else 'BREAK':>12}")

    print("\n" + "=" * 100)
    print("实验 1b 完成")


if __name__ == "__main__":
    main()
