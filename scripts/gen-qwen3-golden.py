#!/usr/bin/env python3
"""生成路线2「真实权重 golden」参考数据（供 gateway/teecore/adapters/qwen 的门控测试消费）。

为什么需要外部参考：Go 侧三条路径（形态A 掩码 / 形态B 掩码 / 参照浮点）共用同一份
前向实现，互相之间"自洽"只能证明掩码链路没写错，**不能证明模型结构实现正确**
（例如 Qwen3 的 QK-norm 放错位置、RoPE 顺序反了，三条路径会一起错且完全同向）。
故必须取一个独立实现（HuggingFace transformers，fp32 CPU）作参照。

用法：
    python scripts/gen-qwen3-golden.py [模型目录] [输出 json]

默认读 .tools/models/Qwen3Guard-Gen-0.6B，写
gateway/teecore/adapters/qwen/testdata/qwen3-06b-golden.json。

注意：本脚本**不是** CI 依赖（CI 无 GPU/torch）；它只在需要重生成基准时手动跑，
产物（小 JSON）入库，Go 测试读产物 + 本地真实权重做对拍。
"""
import json
import sys
from pathlib import Path

import torch
from transformers import AutoModelForCausalLM

# 固定 token 序列（不经 tokenizer，避免两侧分词差异引入噪声；均为该词表内合法 id）
TOKEN_IDS = [151669, 9707, 1879, 13, 1008, 374]
TOP_K = 20


def main() -> int:
    model_dir = Path(sys.argv[1] if len(sys.argv) > 1 else ".tools/models/Qwen3Guard-Gen-0.6B")
    out_path = Path(
        sys.argv[2]
        if len(sys.argv) > 2
        else "gateway/teecore/adapters/qwen/testdata/qwen3-06b-golden.json"
    )
    model = AutoModelForCausalLM.from_pretrained(str(model_dir), torch_dtype=torch.float32)
    model.eval()
    c = model.config

    with torch.no_grad():
        logits = model(input_ids=torch.tensor([TOKEN_IDS])).logits[0, -1]

    top = torch.topk(logits, TOP_K)
    payload = {
        "model": model_dir.name,
        "arch": c.model_type,
        "reference": f"transformers {__import__('transformers').__version__} / torch {torch.__version__} / float32 / CPU",
        "note": "末位 token 的 logits 前 TopK，供 Go 侧 ForwardRef/ForwardMasked 对拍；不得手改",
        "config": {
            "layers": c.num_hidden_layers,
            "dim": c.hidden_size,
            "heads": c.num_attention_heads,
            "kv_heads": c.num_key_value_heads,
            "head_dim": getattr(c, "head_dim", c.hidden_size // c.num_attention_heads),
            "ffn": c.intermediate_size,
            "vocab": c.vocab_size,
            "rope_theta": float(c.rope_theta),
            "norm_eps": float(c.rms_norm_eps),
            "tied": bool(c.tie_word_embeddings),
        },
        "token_ids": TOKEN_IDS,
        "top_k": TOP_K,
        "indices": [int(i) for i in top.indices.tolist()],
        "logits": [round(float(v), 6) for v in top.values.tolist()],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out_path} — top1={payload['indices'][0]} logit={payload['logits'][0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
