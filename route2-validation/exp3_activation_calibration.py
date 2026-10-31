#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exp3 · A5/M1 真实激活分布校准（torch）

目的：用真实预训练小模型统计中间激活分布，确认 R=2^64 + S=1e6 的余量
在真实离群激活下仍充足（exp2 用的是合成 N(0,sigma)，本实验用真实权重 + 真实前向）。

核心不变量（与 masked_linear.go 一致）：
  掩码域内真正参与  mod R  的量是
      T = W_q · xMask          (xMask = round(x * S), S=1e6)
  脱掩码时 bias 被加后减，恰好抵消，故 T 不含 bias。
  解码为 signed(T) * scale / S ≈ W·x。
  当且仅当 |T| > R/2 时发生回绕崩坏。

因此：headroom(R) = (R/2) / max|T| 。
  - R=2^64 → 2^63 / max|T|  应 ≫ 1（安全）
  - R=2^32 → 2^31 / max|T|  应 < 1（崩坏，印证 exp2 / TestM0ModChoice）

运行：python exp3_activation_calibration.py
依赖：torch>=2.7, torchvision>=0.22（本地 Windows py3.12 已具备）
说明：输入用 N(0,1) 张量作压力代理（方差略大于真实归一化图像，结论偏保守）。
"""
import time
import numpy as np
import torch
import torch.nn as nn
import torchvision

S = 1_000_000          # InputScale，与内核一致
R32_HALF = 2**31       # R=2^32 的半幅（回绕阈值）
R64_HALF = 2**63       # R=2^64 的半幅

# 待校准模型（均走 download.pytorch.org，确认可达）
MODELS = [
    ("resnet18", "IMAGENET1K_V1"),
    ("vit_b_16", "IMAGENET1K_V1"),
]


def build_model(name, weights):
    if name == "resnet18":
        return torchvision.models.resnet18(weights=weights)
    if name == "vit_b_16":
        return torchvision.models.vit_b_16(weights=weights)
    raise ValueError(name)


def capture_linear_inputs(model, x):
    """前向一遍，收集所有 nn.Linear 的输入张量（CPU numpy）。"""
    store = []

    def make_hook(mod_name):
        def hook(module, inp, out):
            xin = inp[0].detach().cpu().numpy().astype(np.float64)
            store.append((mod_name, xin))
        return hook

    hooks = []
    for n, m in model.named_modules():
        if isinstance(m, nn.Linear):
            hooks.append(m.register_forward_hook(make_hook(n)))
    with torch.no_grad():
        model(x)
    for h in hooks:
        h.remove()
    return store


def layer_headroom(W, xin, in_chunks=True):
    """
    W: (out, in) float 权重
    xin: (N, in) 一批输入激活（已展平到 (样本数, in)）
    返回该层 int8 / int16 下的 max|T| 与若干分位。
    T = W_q · xMask,  xMask = round(x * S)
    """
    out_f, in_f = W.shape
    maxabsW = float(np.max(np.abs(W)))
    res = {}
    for bit in (8, 16):
        maxQ = float((1 << (bit - 1)) - 1)
        scale = maxabsW / maxQ
        if scale == 0:
            scale = 1.0
        Wq = np.round(W / scale).astype(np.int64)
        # 逐样本精确累加（int64 足够：|(Wq·xMask)| 量级 ~1e12 ≪ 2^63）
        maxT = 0.0
        p99 = 0.0
        allT = []
        for s in range(xin.shape[0]):
            xm = np.round(xin[s] * S).astype(np.int64)
            # 防 int64 溢出保护：若任一项乘积过大，则 Python int 重算
            T = np.dot(Wq, xm)  # (out,)
            if np.any(np.abs(T) > (1 << 62)):
                T = np.array([sum(int(Wq[k, j]) * int(xm[j]) for j in range(in_f))
                              for k in range(out_f)], dtype=np.int64)
            aT = np.abs(T)
            if aT.size:
                mx = float(aT.max())
                if mx > maxT:
                    maxT = mx
                allT.append(mx)
        if allT:
            p99 = float(np.percentile(allT, 99))
        res[bit] = (maxT, p99)
    return res


def main():
    np.random.seed(0)
    torch.manual_seed(0)
    print(f"torch={torch.__version__}  S={S:,}  R32_half={R32_HALF:,}  R64_half={R64_HALF:,}")
    print("=" * 78)

    global_maxT8 = 0.0
    global_maxT16 = 0.0
    global_worst = None

    for mname, wtag in MODELS:
        t0 = time.time()
        try:
            model = build_model(mname, wtag)
        except Exception as e:
            print(f"[SKIP] {mname}: 加载失败 {type(e).__name__}: {e}")
            continue
        model.eval()
        nparams = sum(p.numel() for p in model.parameters())
        print(f"\n### {mname} ({wtag})  参数量={nparams/1e6:.1f}M  加载+校准用时={time.time()-t0:.1f}s")

        # 输入：N(0,1) 压力代理，批量覆盖多个样本（展平 token 维）
        B, batches = 8, 4
        captured = []
        for _ in range(batches):
            x = torch.randn(B, 3, 224, 224)
            captured.extend(capture_linear_inputs(model, x))

        print(f"  捕获 Linear 层: {len(captured)} 个；逐层 max|T|（int8 / int16）：")
        layer_max8 = 0.0
        layer_max16 = 0.0
        worst_layer = None
        for lname, xin in captured:
            # 展平到 (N, in)
            xflat = xin.reshape(-1, xin.shape[-1])
            # 仅取部分样本控制耗时（但覆盖离群）：最多 256 个样本
            if xflat.shape[0] > 256:
                idx = np.random.choice(xflat.shape[0], 256, replace=False)
                xflat = xflat[idx]
            W = None
            # 找到对应权重
            for n, m in model.named_modules():
                if n == lname and isinstance(m, nn.Linear):
                    W = m.weight.detach().cpu().numpy().astype(np.float64)
                    break
            if W is None:
                continue
            rh = layer_headroom(W, xflat)
            mx8, p8 = rh[8]
            mx16, p16 = rh[16]
            layer_max8 = max(layer_max8, mx8)
            layer_max16 = max(layer_max16, mx16)
            if mx8 > (worst_layer[1] if worst_layer else -1):
                worst_layer = (lname, mx8, mx16)
            print(f"    {lname:38s} int8 max|T|={mx8:.3e}  p99={p8:.2e} | int16 max|T|={mx16:.3e}")

        print(f"  >> {mname} 层内最差: int8 max|T|={layer_max8:.3e}  int16 max|T|={layer_max16:.3e}")
        print(f"     最差层: {worst_layer[0] if worst_layer else '-'}")
        if layer_max8 > global_maxT8:
            global_maxT8 = layer_max8
            global_worst = (mname, worst_layer)
        global_maxT16 = max(global_maxT16, layer_max16)

    print("\n" + "=" * 78)
    print("全局最差（跨所有模型/层）:")
    print(f"  int8  max|T| = {global_maxT8:.3e}")
    print(f"  int16 max|T| = {global_maxT16:.3e}")
    h32_8 = R32_HALF / global_maxT8 if global_maxT8 > 0 else float('inf')
    h64_8 = R64_HALF / global_maxT8 if global_maxT8 > 0 else float('inf')
    h64_16 = R64_HALF / global_maxT16 if global_maxT16 > 0 else float('inf')
    print(f"\n  R=2^32 余量(int8)  = {h32_8:.3e}  → {'崩坏' if h32_8 < 1 else '安全'}")
    print(f"  R=2^64 余量(int8)  = {h64_8:.3e}  → {'安全' if h64_8 > 1 else '崩坏'}")
    print(f"  R=2^64 余量(int16) = {h64_16:.3e}  → {'安全' if h64_16 > 1 else '崩坏'}")
    print("\n结论:")
    if h64_8 > 1 and h64_16 > 1:
        print(f"  ✅ R=2^64 + S=1e6 在真实激活下余量充足（int8 ~{h64_8:.1e}x / int16 ~{h64_16:.1e}x），印证 exp2/TestM0ModChoice。")
    if h32_8 < 1:
        print(f"  ✅ R=2^32 + S=1e6 在真实激活下回绕崩坏（余量 {h32_8:.1e}x<1），印证 §7.7 决策：2^32 不可作生产模。")
    if global_worst:
        print(f"  最差层来源: {global_worst[0]} / {global_worst[1][0]}")


if __name__ == "__main__":
    main()
