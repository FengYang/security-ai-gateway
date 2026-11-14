#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check-metrics-green.py —— 指标"全绿"可执行判定（Phase 1 门禁 #9）

定位：把 GA 总览 §6 门禁 #9 的"Prometheus 指标全绿"从**人工判断**变成**可执行门禁**。

判定语义（如实，不做静默降级）：
  清单三列：<source> <metric> <required|conditional>
  - 来源不可达                          → SKIP（不计失败，提示如何拉起）
  - required 指标缺失（来源可达）        → FAIL（"全绿"未达成）
  - conditional 指标缺失                → SKIP（条件注册：其触发事件/开关未发生，非缺陷）

为什么区分 required/conditional：插件计数器为 proxywasm 懒注册（首次 incr 才 Define），
tee-infer 亦然——"从未触发过的计数器不存在"是设计内行为，若一律判 FAIL 则"全绿"永不可达。

用法：
  python3 scripts/check-metrics-green.py
  python3 scripts/check-metrics-green.py --tee http://127.0.0.1:19090 --tee-token <token> \
      --core http://127.0.0.1:8085 --core-token <OTP_CORE_AUTH_TOKEN> \
      --container higress-chain-control-plane
  来源：tee | admin | core | plugin | cryptop | a2a；跳过来源：--skip-tee / --skip-admin / ...

退出码：0 = required 全命中（conditional 可 SKIP）；1 = 存在 FAIL；2 = 脚本自身错误

移植说明（2026-11-14）：本脚本取代 check-metrics-green.ps1，是**唯一实现**（Linux CI 与
  Windows 本地同源）。判据语义与 ps1 版逐条一致，未放宽、未新增跳过路径。
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

# 来源白名单（与清单文件的 <source> 列对应）
SOURCES = ("tee", "admin", "core", "plugin", "cryptop", "a2a")

SOURCE_LABELS = {
    "tee": "tee-infer /metrics",
    "admin": "管理面 /metrics",
    "core": "控制面 /metrics",
    "plugin": "数据面 Envoy stats",
    "cryptop": "cryptop sidecar /metrics",
    "a2a": "A2A 数据面 /metrics",
}


def http_body(url: str, headers: list[tuple[str, str]], timeout: int) -> tuple[bool, str]:
    """抓取 URL 正文。返回 (是否成功, 正文或错误信息)。"""
    req = urllib.request.Request(url, method="GET")
    for k, v in headers:
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as exc:
        return False, str(exc)


def docker_stats(container: str, timeout: int) -> tuple[bool, str]:
    """经容器内 curl 抓 Envoy admin stats（:15000）。返回 (是否成功, 正文)。"""
    try:
        proc = subprocess.run(
            ["docker", "exec", container, "sh", "-c",
             f"curl -s -m {timeout} http://127.0.0.1:15000/stats"],
            capture_output=True, text=True, timeout=timeout + 30,
        )
    except (OSError, subprocess.SubprocessError):
        return False, ""
    body = proc.stdout
    return (proc.returncode == 0 and bool(body.strip())), body


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description="指标全绿判定（门禁 #9）")
    ap.add_argument("--tee", default="http://127.0.0.1:19090")
    ap.add_argument("--tee-token", default="")
    ap.add_argument("--admin", default="http://127.0.0.1:19095")
    ap.add_argument("--core", default="http://127.0.0.1:8085")
    ap.add_argument("--core-token", default="")
    ap.add_argument("--cryptop", default="http://127.0.0.1:19097")
    ap.add_argument("--a2a", default="http://127.0.0.1:19099")
    ap.add_argument("--container", default="higress-chain-control-plane")
    ap.add_argument("--manifest", default=str(here / "metrics-required.txt"))
    ap.add_argument("--timeout", type=int, default=15)
    for s in SOURCES:
        ap.add_argument(f"--skip-{s}", action="store_true", help=f"跳过 {s} 来源")
    # 门禁模式（verify-all 用）：全部来源必须可达，任一个不可达即 FAIL（避免"空跑通过"）
    ap.add_argument("--require-all-sources", action="store_true")
    args = ap.parse_args(argv)

    manifest = Path(args.manifest)
    if not manifest.is_file():
        print(f"清单不存在: {manifest}")
        return 2

    print("===== 指标全绿判定（门禁 #9）=====")

    # ---------- 抓取各来源 ----------
    bodies: dict[str, str] = {}
    ups: dict[str, bool] = {}

    def fetch(src: str, url: str, headers: list[tuple[str, str]]) -> None:
        if getattr(args, f"skip_{src}"):
            print(f"  [SKIP] 按参数跳过 {SOURCE_LABELS[src]}")
            bodies[src], ups[src] = "", False
            return
        ok, body = http_body(url, headers, args.timeout)
        bodies[src], ups[src] = body, ok
        if not ok:
            print(f"  [SKIP] {SOURCE_LABELS[src]} 不可达（{url}）：{body}")

    fetch("tee", f"{args.tee}/metrics", [("X-Admin-Token", args.tee_token)] if args.tee_token else [])
    fetch("admin", f"{args.admin}/metrics", [])
    fetch("core", f"{args.core}/metrics", [("Authorization", f"Bearer {args.core_token}")] if args.core_token else [])
    fetch("cryptop", f"{args.cryptop}/metrics", [])
    fetch("a2a", f"{args.a2a}/metrics", [])

    if getattr(args, "skip_plugin"):
        print(f"  [SKIP] 按参数跳过 {SOURCE_LABELS['plugin']}")
        bodies["plugin"], ups["plugin"] = "", False
    else:
        ok, body = docker_stats(args.container, args.timeout)
        bodies["plugin"], ups["plugin"] = body, ok
        if not ok:
            print(f"  [SKIP] 数据面 stats 不可达（容器 {args.container} :15000）")

    # ---------- 逐条断言 ----------
    results: list[tuple[str, str, str, str, str]] = []  # (source, metric, kind, status, detail)

    for raw in manifest.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            results.append(("manifest", line, "required", "FAIL",
                            "清单格式非法（应为 <source> <metric> [required|conditional]）"))
            continue
        src, metric = parts[0], parts[1]
        kind = parts[2] if len(parts) >= 3 else "required"

        if src not in SOURCES:
            results.append((src, metric, kind, "FAIL", f"未知来源: {src}"))
            continue

        if not ups[src]:
            if args.require_all_sources:
                results.append((src, metric, kind, "FAIL",
                                f"{SOURCE_LABELS[src]} 不可达（门禁模式要求全部来源可达）"))
            else:
                results.append((src, metric, kind, "SKIP", f"{SOURCE_LABELS[src]} 不可达"))
            continue

        if metric in bodies[src]:
            results.append((src, metric, kind, "PASS", ""))
            continue
        if kind == "conditional":
            results.append((src, metric, kind, "SKIP",
                            "条件指标未触发（设计内：懒注册，其事件/开关未发生）"))
            continue
        results.append((src, metric, kind, "FAIL", f"{SOURCE_LABELS[src]} 缺失且为 required"))

    # ---------- 汇总 ----------
    n_pass = sum(1 for r in results if r[3] == "PASS")
    n_fail = sum(1 for r in results if r[3] == "FAIL")
    n_skip = sum(1 for r in results if r[3] == "SKIP")
    req_fail = sum(1 for r in results if r[3] == "FAIL" and r[2] == "required")

    for src, metric, kind, status, detail in results:
        if status != "PASS":
            print(f"[{status}] {src} {metric} ({kind}) {detail}")

    print("\n===== 汇总 =====")
    print(f"PASS={n_pass} FAIL={n_fail} SKIP={n_skip}（清单 {len(results)} 条；required 失败 {req_fail}）")
    if n_skip > 0:
        print('说明（如实）：SKIP 分两类——来源不可达 / conditional 未触发；两类都不等于"全绿"')
        print('      宣布"全绿"口径 = 全部来源可达 且 required 全命中（本脚本退出码 0 且 SKIP 中无"来源不可达"）')
    return 1 if n_fail > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
