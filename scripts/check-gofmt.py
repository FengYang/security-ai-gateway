#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check-gofmt.py —— 增量 gofmt 门禁

Purpose: fail CI when newly added/modified .go files are not gofmt-clean.
Rationale: the repository still carries legacy gofmt drift in several packages,
  so a full-repo check would fail today; this gate only checks the .go files that
  changed in the current change set (base..HEAD). Once the whole tree is clean the
  gate can be widened to a full-repo check.

Usage:
  python3 scripts/check-gofmt.py --base origin/master
  python3 scripts/check-gofmt.py --base HEAD^
  python3 scripts/check-gofmt.py                  # 默认 HEAD^..HEAD

退出码：0 = 变更文件均 gofmt-clean 或无变更；1 = 存在未格式化文件；2 = 环境问题（git/gofmt 缺失）

移植说明（2026-11-14）：本脚本取代 check-gofmt.ps1，是**唯一实现**。
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def find_gofmt() -> str | None:
    """定位 gofmt：PATH → GOROOT/bin → 常见安装路径。"""
    exe = "gofmt.exe" if os.name == "nt" else "gofmt"

    found = shutil.which("gofmt")
    if found:
        return found

    # 退路 1：go env GOROOT
    go = shutil.which("go")
    if go:
        try:
            proc = subprocess.run([go, "env", "GOROOT"], capture_output=True, text=True, timeout=30)
            if proc.returncode == 0 and proc.stdout.strip():
                cand = Path(proc.stdout.strip()) / "bin" / exe
                if cand.is_file():
                    return str(cand)
        except (OSError, subprocess.SubprocessError):
            pass

    # 退路 2：常见安装路径（本仓库开发机/CI 机的实际布局）
    for cand in (Path("/usr/local/go/bin") / exe,
                 Path(r"C:\Program Files\Go\bin") / exe):
        if cand.is_file():
            return str(cand)
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="增量 gofmt 门禁")
    ap.add_argument("--base", default="", help="基线 ref（PR base / 上一提交）；缺省用 HEAD^")
    args = ap.parse_args(argv)

    repo_root = Path(__file__).resolve().parent.parent
    os.chdir(repo_root)

    gofmt = find_gofmt()
    if not gofmt:
        print("gofmt gate ERROR: 找不到 gofmt（PATH / GOROOT/bin / /usr/local/go/bin 均无）")
        return 2

    # Diff range: explicit base (PR base / previous commit) when provided, else HEAD^.
    rng = f"{args.base}...HEAD" if args.base else "HEAD^...HEAD"

    try:
        proc = subprocess.run(["git", "diff", "--name-only", rng, "--", "*.go"],
                              capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"gofmt gate ERROR: git diff 执行失败（{exc}）")
        return 2
    if proc.returncode != 0:
        # 与 ps1 版一致：diff 失败按"无变更"处理会造假绿，故显式报错。
        print(f"gofmt gate ERROR: git diff 失败（range={rng}）：{proc.stderr.strip()}")
        return 2

    files = [f for f in proc.stdout.splitlines() if f.strip() and Path(f).exists()]
    if not files:
        print(f"gofmt gate: no changed .go files in '{rng}'; skip.")
        return 0

    try:
        bad_proc = subprocess.run([gofmt, "-l", *files], capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"gofmt gate ERROR: gofmt 执行失败（{exc}）")
        return 2

    bad = [ln for ln in bad_proc.stdout.splitlines() if ln.strip()]
    if bad:
        print("gofmt gate FAIL: the following changed .go files are not gofmt-clean:")
        for b in bad:
            print(f"  {b}")
        print("Fix locally with: gofmt -w <files>")
        return 1

    print(f"gofmt gate PASS: {len(files)} changed .go file(s) are gofmt-clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
