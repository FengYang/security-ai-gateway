#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""l2-smoke.py —— L2 两段式端到端冒烟（Qwen3Guard Q8_0 llama-server + 侧车 + HTTP 客户端）

前置（缺任一则 SKIP，exit 0，不阻塞 CI —— 与 CI 原内联步骤语义一致）：
  .tools/models/Qwen3Guard-Gen-0.6B-GGUF/Qwen3Guard-Gen-0.6B.Q8_0.gguf
  .tools/llamacpp/llama-server          （Windows 为 llama-server.exe）
  .tools/models/Qwen3Guard-Gen-0.6B/    （侧车模型目录）

流程：起 llama-server(:19110) → 等 /health → 起侧车(:19112) → scripts/og1b-smoke.py → 清理

退出码：0 = 通过或 SKIP；1 = 冒烟断言失败

移植说明（2026-11-14）：本脚本取代 ci.yml 里内联的 pwsh 步骤（`Start-Process` /
  `Invoke-WebRequest` / `Test-Path`），成为**唯一实现**，Linux 与 Windows 同源。
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

GGUF = ".tools/models/Qwen3Guard-Gen-0.6B-GGUF/Qwen3Guard-Gen-0.6B.Q8_0.gguf"
MODEL_DIR = ".tools/models/Qwen3Guard-Gen-0.6B"


def find_llama(root: Path) -> Path | None:
    """定位 llama-server：Linux 无后缀，Windows 为 .exe。"""
    for name in ("llama-server", "llama-server.exe"):
        cand = root / ".tools" / "llamacpp" / name
        if cand.is_file():
            return cand
    return None


def wait_health(url: str, attempts: int = 30, sleep_s: float = 2.0) -> bool:
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, urllib.error.HTTPError, OSError):
            time.sleep(sleep_s)
    return False


def main(argv: list[str] | None = None) -> int:
    # 行缓冲：子进程（llama-server/sidecar）直接继承 stdout，若不刷新会与主进程
    # 的进度输出交错，导致日志顺序错乱、误导排障。
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

    ap = argparse.ArgumentParser(description="L2 two-stage smoke")
    ap.add_argument("--llama-port", type=int, default=19110)
    ap.add_argument("--sidecar-port", type=int, default=19112)
    args = ap.parse_args(argv)

    root = Path(__file__).resolve().parent.parent
    gguf = root / GGUF
    llama = find_llama(root)
    model_dir = root / MODEL_DIR

    if not gguf.is_file() or llama is None:
        print(f"SKIP: llama-server or GGUF not found (expected at {llama} / {gguf})")
        return 0
    if not model_dir.is_dir():
        print(f"SKIP: sidecar model dir not found (expected at {model_dir})")
        return 0

    python = sys.executable or shutil.which("python3") or "python3"
    sidecar = root / "scripts" / "qwen3guard-l2-sidecar.py"
    smoke = root / "scripts" / "og1b-smoke.py"
    for need in (sidecar, smoke):
        if not need.is_file():
            print(f"SKIP: 缺少脚本 {need}")
            return 0

    llama_url = f"http://127.0.0.1:{args.llama_port}"
    sidecar_url = f"http://127.0.0.1:{args.sidecar_port}"

    print(f"启动 llama-server: {llama}")
    llama_proc = subprocess.Popen(
        [str(llama), "-m", str(gguf), "--host", "127.0.0.1",
         "--port", str(args.llama_port), "-np", "2", "-c", "2048", "-t", "4"],
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )
    sidecar_proc: subprocess.Popen | None = None
    try:
        if not wait_health(f"{llama_url}/health"):
            print("FAIL: llama-server /health 未就绪（30 次 × 2s）")
            return 1
        print("llama-server 就绪")

        print(f"启动侧车: {sidecar}")
        sidecar_proc = subprocess.Popen(
            [python, str(sidecar), "--model-dir", str(model_dir),
             "--port", str(args.sidecar_port), "--llama-url", llama_url],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
        )
        time.sleep(5)

        print(f"$ {python} {smoke} --sidecar {sidecar_url}")
        proc = subprocess.run([python, str(smoke), "--sidecar", sidecar_url], timeout=1800)
        if proc.returncode != 0:
            print(f"FAIL: smoke test failed with exit {proc.returncode}")
            return 1
        print("PASS: L2 two-stage smoke")
        return 0
    finally:
        for p, label in ((sidecar_proc, "sidecar"), (llama_proc, "llama-server")):
            if p is not None and p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    p.kill()
                print(f"已停止 {label}")


if __name__ == "__main__":
    sys.exit(main())
