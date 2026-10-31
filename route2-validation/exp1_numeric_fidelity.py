#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
路线 2（掩码像推理）· 实验 1：数值保真度与安全域边界验证

对应假设
--------
H1：按 masked_linear.go 语义，掩码线性层可持续使用的前提是
      |result| < 2^31 / 1e6 = 2147.483648   （超出即模环绕 => 灾难性错误）
      且 int64 累加器 acc 不溢出（被掩码后 V 为 ~2^32 量级）

分项实验
--------
E1.1 单层：掩码路径 vs float32 参考的误差量级（bit=8/16，dim=768/2048/4096）
E1.2 环绕边界扫描：真实放大权重使输出落到目标量级，验证 2147.48 这个硬边界
E1.3 深度累积：端到端堆叠 L 层，掩码链 vs 明文链，看误差是否随深度发散
E1.4 int64 溢出上界：Cols * max|Wq| * max|V| vs 2^63，跨 bit 宽度与常见宽度

算法语义（逐行移植自 gateway/teecore/maskedinfer/masked_linear.go）
------------------------------------------------------------------
  R = 2^32
  量化：   scale = max|W| / (2^(b-1)-1)， Wq = round(W/scale)
  掩码域：  V = (trunc(x*1e6) + r) mod R ， r ~ U[0,R)
  Acc：    acc = sum_i Wq[j,i]*V[i] (+bias_q)
  回乘：   val = float64(acc) * scale ； y_c = int64(trunc(val)) mod R
  掩码像：  对 r 走同样 acc/val 流程 -> image
  脱掩码：  y = (y_c - image) mod R ； SignedValue 解释有符号 ； result = y/1e6

依赖与运行
--------
  pip install numpy
  python exp1_numeric_fidelity.py

说明：本机 CPU-only Windows，无 GPU/TEE。本实验测的是「算法数值性质」，
      属硬件中立的结构性结论，对 Linux 真机同样成立。
"""

import numpy as np

MASK_MOD = 1 << 32
HALF_MOD = 1 << 31
INPUT_SCALE = 1e6
INT64_LIMIT = 1 << 63


# ---------------- 移植：量化 ----------------
def quantize_matrix(W: np.ndarray, bit_width: int):
    """对称量化，与 NewQuantizedMatrix 一致。返回 (Wq int32, scale float)"""
    max_w = float(np.max(np.abs(W)))
    if max_w == 0.0:
        raise ValueError("权重全零")
    max_q = float((1 << (bit_width - 1)) - 1)
    scale = max_w / max_q
    return np.round(W / scale).astype(np.int32), scale


# ---------------- 移植：掩码域 ----------------
def to_mask_domain(x: np.ndarray) -> np.ndarray:
    """float -> int64: trunc(x*1e6) mod R，对应 FloatToMaskDomain"""
    return np.mod(np.trunc(np.asarray(x, dtype=np.float64) * INPUT_SCALE).astype(np.int64), MASK_MOD)


def draw_mask(shape, rng) -> np.ndarray:
    return rng.integers(0, MASK_MOD, size=shape, dtype=np.uint64).astype(np.int64)


# ---------------- 移植：核心三项 ----------------
def _acc(Wq: np.ndarray, V: np.ndarray, bias_q=None) -> np.ndarray:
    """int64 逐项乘后求和，对应 Go 的 int64 acc 累加"""
    prod = (Wq.astype(np.int64) * V[np.newaxis, :]).astype(np.int64)
    acc = prod.sum(axis=1)
    if bias_q is not None:
        acc = acc + bias_q.astype(np.int64)
    return acc


def _acc_to_domain(acc: np.ndarray, scale: float) -> np.ndarray:
    """val = float64(acc)*scale -> trunc -> int64 -> mod R"""
    val = acc.astype(np.float64) * scale
    return np.mod(np.trunc(val).astype(np.int64), MASK_MOD)


def unmask(y_cipher: np.ndarray, image: np.ndarray) -> np.ndarray:
    return np.mod(y_cipher.astype(np.int64) - image.astype(np.int64), MASK_MOD)


def signed_value(v: np.ndarray) -> np.ndarray:
    v = np.asarray(v, dtype=np.int64)
    return np.where(v >= HALF_MOD, v - MASK_MOD, v)


def recover(v_signed: np.ndarray) -> np.ndarray:
    return v_signed.astype(np.float64) / INPUT_SCALE


# ---------------- 一次完整掩码线性层 ----------------
def masked_linear(W_true: np.ndarray, x: np.ndarray, bit_width: int, rng):
    """
    返回 (masked_out, plain_ref, max_abs_acc)
    注意：生产实现中 r 与 W*r 由预处理方持有；此处为数值验证，
         由 V 与不失真的 x*1e6 反推 r，等价于同一条数据通路。
    """
    Wq, scale = quantize_matrix(W_true, bit_width)
    x_dom = to_mask_domain(x)
    r = draw_mask(x.shape, rng)
    V = np.mod(x_dom + r, MASK_MOD)

    y_c = _acc_to_domain(_acc(Wq, V), scale)
    img = _acc_to_domain(_acc(Wq, r), scale)
    out = recover(signed_value(unmask(y_c, img)))
    return out, (W_true @ x), int(np.max(np.abs(_acc(Wq, V))))


def err_stats(got, ref):
    err = np.abs(got - ref)
    rel = err / np.maximum(np.abs(ref), 1e-12)
    return float(np.max(err)), float(np.mean(err)), float(np.max(rel))


def main():
    rng = np.random.default_rng(20261031)

    print("=" * 80)
    print("路线 2 掩码像推理 —— 实验 1：数值保真度与安全域边界")
    print("算法来源: gateway/teecore/maskedinfer/masked_linear.go (1:1 语义移植)")
    print("=" * 80)

    # ---------- E1.1 单层正确性 ----------
    print("\n[E1.1] 单层：掩码路径 vs float32 参考")
    print(f"{'bit':>4}{'out':>7}{'in':>7}{'maxAbsErr':>14}{'meanAbsErr':>14}{'maxRel':>14}{'acc_max':>16}{'溢出上界':>10}")
    for bit in (8, 16):
        for dim in (768, 2048, 4096):
            W = rng.normal(0, 0.02, size=(dim, dim))
            x = rng.normal(0, 1.0, size=dim)
            Wq, _ = quantize_matrix(W, bit)
            worst = dim * int(np.max(np.abs(Wq.astype(np.int64)))) * (MASK_MOD - 1)
            ok = worst < INT64_LIMIT
            got, ref, acc_max = masked_linear(W, x, bit, np.random.default_rng(1))
            mx, mn, mr = err_stats(got, ref)
            print(f"{bit:>4}{dim:>7}{dim:>7}{mx:>14.3e}{mn:>14.3e}{mr:>14.3e}{acc_max:>16.3e}"
                  f"{'OK' if ok else 'AT-RISK':>10}")

    # ---------- E1.2 环绕边界扫描 ----------
    print("\n[E1.2] 环绕边界扫描：真实放大权重使 |W@x| 落到目标量级")
    print("       理论硬边界 |result| < 2^31/1e6 = 2147.483648")
    print(f"{'目标|y|':>12}{'实测max|y|':>14}{'maxAbsErr':>14}{'maxRel':>14}{'判定':>14}")
    dim = 1024
    x = rng.normal(0, 1.0, size=dim)
    W0 = rng.normal(0, 0.02, size=(dim, dim))
    base = W0 @ x
    base_max = float(np.max(np.abs(base)))
    for target in (1.0, 10.0, 100.0, 1000.0, 2000.0, 2147.0, 2200.0, 5000.0, 1e5):
        kw = target / base_max
        W = W0 * kw
        got, ref, _ = masked_linear(W, x, 8, np.random.default_rng(7))
        mx, _, mr = err_stats(got, ref)
        real_max = float(np.max(np.abs(ref)))
        good = (mx < 1e-2) and (mr < 1e-2)
        print(f"{target:>12.1f}{real_max:>14.3e}{mx:>14.3e}{mr:>14.3e}{'OK' if good else 'BREAK(环绕)':>14}")

    # ---------- E1.3 深度累积 ----------
    print("\n[E1.3] 深度累积：掩码链 vs 明文链（同一组权重序列）")
    print(f"{'层数L':>7}{'掩码链末端max|y|':>18}{'明文链末端max|y|':>18}{'末端maxAbsErr':>16}{'末端maxRel':>14}")
    for L in (1, 4, 12, 32):
        dim = 512
        x0 = rng.normal(0, 1.0, size=dim)
        Ws = [rng.normal(0, 0.02, size=(dim, dim)) for _ in range(L)]
        cur_m = x0.copy()
        cur_p = x0.copy()
        for i, W in enumerate(Ws):
            cur_m, _, _ = masked_linear(W, cur_m, 8, np.random.default_rng(100 + i))
            cur_p = W @ cur_p
        mx, _, mr = err_stats(cur_m, cur_p)
        print(f"{L:>7}{float(np.max(np.abs(cur_m))):>18.3e}{float(np.max(np.abs(cur_p))):>18.3e}"
              f"{mx:>16.3e}{mr:>14.3e}")

    # ---------- E1.4 int64 溢出上界 ----------
    print("\n[E1.4] int64 累加溢出上界：Cols * max|Wq| * max|V|  vs  2^63 = 9.223e18")
    print(f"{'bit':>5}{'max|Wq|':>9}{'Cols':>8}{'worst':>22}{'余量倍数':>12}{'判定':>10}")
    for bit, mw in ((8, 127), (16, 32767)):
        for cols in (768, 2048, 4096, 11008, 28672):
            worst = cols * mw * (MASK_MOD - 1)
            head = (2 ** 63) / worst
            print(f"{bit:>5}{mw:>9}{cols:>8}{worst:>22.3e}{head:>12.2f}x{'OK' if worst < 2**63 else 'AT-RISK':>10}")

    print("\n" + "=" * 80)
    print("实验 1 完成")


if __name__ == "__main__":
    main()
