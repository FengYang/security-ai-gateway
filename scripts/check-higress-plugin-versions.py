#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check-higress-plugin-versions.py —— Higress 插件版本门禁（防"静默不生效"漂移）

背景：插件 URL 里的版本号一旦与镜像实际安装版本不一致，wasm 加载会 404；配合 FAIL_OPEN
      时请求被静默放行（认证/限流全部失效），线上不会明显报错，属"静默事故"。
      本项目已在 2026-09-12 实际踩到（3 个插件 1.x URL 在 2.x 镜像上全部 404）。

校验两个方向：
  A. 仓库 ↔ 锁定文件：扫描仓库内全部 `plugins/<name>/<version>/plugin.wasm` 引用，
     与 deploy/higress/plugin-versions.lock 对照；未登记插件或版本不一致 → 失败。
  B. 锁定文件 ↔ 运行镜像（可选，传 --container）：读镜像插件目录版本，与锁定文件对照；
     镜像升级导致版本漂移 → 失败（提醒同步清单与锁定文件）。

用法：
  python3 scripts/check-higress-plugin-versions.py
  python3 scripts/check-higress-plugin-versions.py --container higress-chain-control-plane

退出码：0 = 通过；1 = 存在未登记引用 / 版本漂移 / 锁定文件不可解析。

移植说明（2026-11-14）：本脚本取代 check-higress-plugin-versions.ps1，是**唯一实现**。
  Linux CI 与 Windows 本地跑同一份代码，避免 sh/ps1 双实现漂移。
  相对 ps1 版唯一的行为变化：扫描后缀集新增 `.py`（ps1 版未覆盖，属漏检面）。
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

# 仓库内 plugin.wasm 引用：plugins/<name>/<version>/plugin.wasm
REF_RE = re.compile(r"plugins/([A-Za-z0-9._-]+)/([0-9][0-9A-Za-z.\-]*)/plugin\.wasm")
# 锁定文件条目：<name>=<version>
LOCK_RE = re.compile(r"^([A-Za-z0-9._-]+)=([0-9][0-9A-Za-z.\-]*)$")

# 参与扫描的后缀（源码与清单；二进制/工件不扫）
SCAN_SUFFIXES = {".yaml", ".yml", ".md", ".json", ".ps1", ".sh", ".go", ".py"}
# 排除目录：依赖、非源码、本地运行态快照
#   higress-standalone：wasmplugins/*.yaml 由 Higress 控制台写入、会被覆盖，不作为"部署清单"校验对象
#   .tools             ：本仓 .gitignore 忽略的本地开发工件目录（未跟踪 ⇒ 不构成仓库部署清单）。
#                        排除它只为提速；CI checkout 本就没有该目录，判定结果不受影响。
EXCLUDE_DIRS = {"vendor", "node_modules", ".git", "higress-standalone", ".tools"}
# 单文件上限：超大文件不可能是部署清单引用源，跳过以免拖慢扫描
MAX_BYTES = 2 * 1024 * 1024


def fail(msg: str) -> None:
    print(msg)


def parse_lock(lock_path: Path) -> tuple[dict[str, str], bool]:
    """解析锁定文件。返回 (条目, 是否有非法行)。"""
    lock: dict[str, str] = {}
    bad = False
    # utf-8-sig：容忍 BOM（文件由 Windows 侧生成过）
    for raw in lock_path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = LOCK_RE.match(line)
        if not m:
            fail(f"[FAIL] 锁定文件存在非法行：{line}")
            bad = True
            continue
        lock[m.group(1)] = m.group(2)
    return lock, bad


def scan_refs(root: Path) -> list[tuple[str, str, str, int]]:
    """扫描仓库内 plugin.wasm 引用。返回 [(plugin, version, relpath, lineno)]。

    用 os.walk 并**剪枝**排除目录（而非 rglob 后过滤）：后者会进入 .git/ 的对象树，
    在真实仓库上白耗 2 分钟以上。
    """
    refs: list[tuple[str, str, str, int]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() not in SCAN_SUFFIXES:
                continue
            try:
                if path.stat().st_size > MAX_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = path.relative_to(root).as_posix()
            for lineno, line in enumerate(text.splitlines(), start=1):
                for m in REF_RE.finditer(line):
                    refs.append((m.group(1), m.group(2), rel, lineno))
    return refs


def check_container(container: str, lock: dict[str, str]) -> bool:
    """方向 B：锁定文件 ↔ 运行镜像。返回是否发现漂移。"""
    print(f"--- 校验镜像插件版本（container={container}）---")
    try:
        proc = subprocess.run(
            ["docker", "exec", container, "find", "/usr/share/nginx/html/plugins",
             "-mindepth", "2", "-maxdepth", "2", "-type", "d"],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"[WARN] 无法读取镜像插件目录（容器未运行或路径不同）；跳过方向 B（{exc}）")
        return False

    out = proc.stdout.strip()
    if proc.returncode != 0 or not out:
        print("[WARN] 无法读取镜像插件目录（容器未运行或路径不同）；跳过方向 B")
        return False

    image: dict[str, str] = {}
    for p in out.splitlines():
        seg = re.sub(r"^.*/plugins/", "", p.strip()).split("/")
        if len(seg) == 2:
            image[seg[0]] = seg[1]
    print(f"镜像插件数 = {len(image)}")

    drift: list[str] = []
    for name, ver in lock.items():
        if name not in image:
            drift.append(f"{name}: 镜像缺失（锁定={ver}）")
        elif image[name] != ver:
            drift.append(f"{name}: 锁定={ver} 镜像={image[name]}")

    if drift:
        print("[FAIL] 锁定文件与镜像版本漂移（镜像升级后需同步清单与锁定文件）：")
        for d in drift:
            print(f"        {d}")
        return True
    print("[PASS] 锁定文件与镜像版本一致")
    return False


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description="Higress 插件版本门禁")
    ap.add_argument("--lock-file", default=str(here.parent / "deploy" / "higress" / "plugin-versions.lock"))
    ap.add_argument("--root", default=str(here.parent))
    ap.add_argument("--container", default="", help="可选：docker 容器名，启用方向 B 校验")
    args = ap.parse_args(argv)

    lock_path = Path(args.lock_file).resolve()
    root = Path(args.root).resolve()

    # ---------- 1. 解析锁定文件 ----------
    if not lock_path.is_file():
        print(f"[FAIL] 锁定文件不存在：{lock_path}")
        return 1
    lock, bad = parse_lock(lock_path)
    print(f"锁定插件数 = {len(lock)}")

    # ---------- 2. 方向 A：仓库引用 ↔ 锁定 ----------
    refs = scan_refs(root)
    print(f"仓库内 plugin.wasm 引用 = {len(refs)}")

    failed = bad

    unknown = [(p, v, f, ln) for (p, v, f, ln) in refs if p not in lock]
    if unknown:
        failed = True
        print("[FAIL] 未在锁定文件登记的插件引用：")
        for p, v, f, ln in sorted(set(unknown)):
            print(f"        {p} {v}   （{f}:{ln}）")

    drift = [(p, v, f, ln, lock[p]) for (p, v, f, ln) in refs if p in lock and lock[p] != v]
    if drift:
        failed = True
        print("[FAIL] 版本与锁定文件不一致：")
        for p, v, f, ln, locked in sorted(set(drift)):
            print(f"        {p}: 引用={v} 锁定={locked}   （{f}:{ln}）")

    referenced = {p for (p, _v, _f, _ln) in refs}
    unused = sorted(k for k in lock if k not in referenced)
    if unused:
        print(f"[WARN] 锁定文件中未被仓库引用的条目（可能为预留/已停用）：{', '.join(unused)}")

    if not failed:
        # 去重后排序输出（与 ps1 的 Sort-Object Plugin, Version -Unique 等价）
        print("[PASS] 仓库引用与锁定文件一致：")
        for p, v in sorted({(p, v) for (p, v, _f, _ln) in refs}):
            print(f"        {p} = {v}")

    # ---------- 3. 方向 B（可选）：锁定 ↔ 运行镜像 ----------
    if args.container:
        if check_container(args.container, lock):
            failed = True

    if failed:
        return 1
    print("[PASS] Higress 插件版本门禁通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
