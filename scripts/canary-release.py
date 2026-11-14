#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""canary-release.py —— tee-infer-service 金丝雀发布 / 回滚（C-7）

原理：canary Deployment 与稳定版共用 Service 选择器（app: tee-infer-service），
      副本数比例即流量比例（无集群时支持 --dry-run 打印将执行的命令）。

用法（需 kubectl + 集群）：
  python3 scripts/canary-release.py deploy   --tag v2.0.0                # 部署 canary（新 tag）
  python3 scripts/canary-release.py weight   --canary 1 --stable 2       # 1/3 流量给 canary
  python3 scripts/canary-release.py promote  --tag v2.0.0                # 稳定版升级新 tag，收 canary
  python3 scripts/canary-release.py rollback --tag v1.0.0                # 回滚稳定版，收 canary
  python3 scripts/canary-release.py status                               # 当前副本/镜像状态
  python3 scripts/canary-release.py deploy   --tag v2.0.0 --dry-run      # 无集群演练

退出码：0 = 成功；1 = 参数或执行错误

移植说明（2026-11-14）：本脚本取代 canary-release.ps1，是**唯一实现**。
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

NS = "otpmask"
STABLE_DEP = "tee-infer-service"
CANARY_DEP = "tee-infer-canary"


def exec_kubectl(cmdline: list[str], dry_run: bool) -> int:
    shown = " ".join(["kubectl", *cmdline])
    if dry_run:
        print(f"[dry-run] {shown}")
        return 0
    print(f"$ {shown}")
    try:
        proc = subprocess.run(["kubectl", *cmdline], timeout=600)
        return proc.returncode
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"错误：kubectl 执行失败（{exc}）")
        return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="tee-infer-service 金丝雀发布 / 回滚")
    ap.add_argument("action", choices=["deploy", "weight", "promote", "rollback", "status"])
    ap.add_argument("--tag", default="latest")
    ap.add_argument("--canary", type=int, default=1)
    ap.add_argument("--stable", type=int, default=2)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    root = Path(__file__).resolve().parent.parent
    tmpl = root / "deploy" / "k8s" / "canary" / "tee-infer-canary.yaml"
    dry = args.dry_run
    rc = 0

    if args.action == "deploy":
        if args.tag == "latest":
            print("错误：deploy 需指定 --tag（如 v2.0.0）")
            return 1
        if not tmpl.is_file():
            print(f"错误：canary 模板不存在：{tmpl}")
            return 1
        yaml_text = tmpl.read_text(encoding="utf-8").replace("__TAG__", args.tag)

        # 临时文件：Windows 用 delete=False + 手动清理；POSIX 同理，避免句柄占用
        fd, tmp_name = tempfile.mkstemp(prefix="tee-infer-canary-", suffix=".yaml")
        os.close(fd)
        tmp = Path(tmp_name)
        try:
            tmp.write_text(yaml_text, encoding="utf-8")
            if dry:
                print(f"[dry-run] kubectl apply -f {tmp} (image tag={args.tag})")
            else:
                rc = exec_kubectl(["apply", "-f", str(tmp)], False)
        finally:
            tmp.unlink(missing_ok=True)
        if rc == 0:
            print(f"canary 已部署（tag={args.tag}）；下一步：weight 调整流量比例")
        return rc

    if args.action == "weight":
        rc |= exec_kubectl(["scale", "deployment", STABLE_DEP, "-n", NS, f"--replicas={args.stable}"], dry)
        rc |= exec_kubectl(["scale", "deployment", CANARY_DEP, "-n", NS, f"--replicas={args.canary}"], dry)
        total = args.stable + args.canary
        pct = round(args.canary * 100.0 / total, 1) if total else 0.0
        print(f"流量比例：canary {args.canary}/{total}（约 {pct}%） stable {args.stable}/{total}")
        return rc

    if args.action in ("promote", "rollback"):
        if args.tag == "latest":
            print(f"错误：{args.action} 需指定 --tag（目标版本）")
            return 1
        rc |= exec_kubectl(["set", "image", f"deployment/{STABLE_DEP}", "-n", NS,
                            f"tee-infer-service=otpmask/tee-infer-service:{args.tag}"], dry)
        rc |= exec_kubectl(["scale", "deployment", CANARY_DEP, "-n", NS, "--replicas=0"], dry)
        if rc == 0:
            verb = "升级到" if args.action == "promote" else "回滚到"
            print(f"稳定版已{verb} {args.tag}，canary 已收量（保留 Deployment 便于快速回滚）")
        return rc

    # status
    exec_kubectl(["get", "deploy", f"{STABLE_DEP},{CANARY_DEP}", "-n", NS, "-o", "wide"], dry)
    exec_kubectl(["get", "pods", "-n", NS, "-l", "app=tee-infer-service", "-o", "wide"], dry)
    return 0


if __name__ == "__main__":
    sys.exit(main())
