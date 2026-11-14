#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify-k8s.py —— M10 K8s 清单校验（无需集群）

校验项：
  1. kustomize 渲染      kubectl kustomize deploy/{k8s,monitoring}，须含 kind: Deployment
  2. YAML 语法           deploy/**/*.yaml 逐文档 yaml.safe_load_all（排除 Helm templates/）
  3. kubectl dry-run     有集群上下文时 apply --dry-run=server；无集群则如实标注 skipped
  4. Go 服务可构建       gateway/tee-infer-service + gateway/embedding-service
  5. 镜像可构建          otpmask/envoy-gateway（wasm 已打包）
  6. Helm chart          helm lint + template（带 ci-values）/ 无值必须失败（secret 必填守卫）
  7. kind 真集群（可选） --kind

Usage:
  python3 scripts/verify-k8s.py
  python3 scripts/verify-k8s.py --kind

退出码：0 = 全部 PASS；1 = 至少一项 FAIL

移植说明（2026-11-14）：本脚本取代 verify-k8s.ps1，是**唯一实现**；verify-all.py 直接调用它
  （ps1 版靠 `cmd /c powershell` 嵌套调用，Linux 不可用）。
  相对 ps1 版的两处**加严/修正**（均不改变判据含义）：
    a) `go build` 显式带 `-mod=mod`：本仓库含 vendor/ 但无 modules.txt，裸 go 会
       inconsistent vendoring 必然失败；ps1 版实际靠环境变量 GOFLAGS=-mod=mod 隐式生效。
    b) Helm/tool 缺失时 ps1 判 PASS(skipped)，本版保持同一口径（如 skip 会打印明细），
       但 Go/kustomize/YAML 这类**无外部依赖**的项绝不 skip。
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

RESULTS: list[tuple[str, str, str]] = []  # (name, status, detail)


def check(name: str, ok: bool, detail: str = "") -> None:
    status = "PASS" if ok else "FAIL"
    RESULTS.append((name, status, detail))
    print(f"[{status}] {name} {detail}".rstrip())


def run(cmd: list[str], timeout: int = 600, cwd: Path | None = None) -> tuple[int, str]:
    """执行命令，返回 (exit code, stdout+stderr)。不抛异常（除缺可执行时返回 127）。"""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except FileNotFoundError:
        return 127, f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s: {' '.join(cmd)}"
    except OSError as exc:
        return 126, f"exec error: {exc}"


def flat(text: str, limit: int = 300) -> str:
    """把多行输出压成单行摘要（与 ps1 的 `-replace "`n", ' '` 等价）。"""
    s = " ".join(text.split())
    return s[:limit]


def tail(text: str, limit: int = 240) -> str:
    """压成单行摘要：优先取含 error 的行（根因），否则取末尾几行。

    kubectl 会把 Warning 混在输出末尾，单纯 tail 会漏掉真正的 `error:` 行。
    """
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    err = [ln for ln in lines if "error" in ln.lower()]
    picked = err if err else lines[-4:]
    return " | ".join(picked)[:limit]


def find_go() -> str | None:
    """定位 go：GO_BIN → PATH → GOROOT → 常见安装路径。

    必须带退路：真实 Linux 机器常把 go 装在 /usr/local/go/bin 而**不进 PATH**
    （本仓验证机即如此）。只查 PATH 会让门禁在换机后误红，且错误信息指向"环境"而非代码。
    """
    if os.environ.get("GO_BIN"):
        return os.environ["GO_BIN"]
    found = shutil.which("go")
    if found:
        return found
    exe = "go.exe" if os.name == "nt" else "go"
    for cand in (Path("/usr/local/go/bin") / exe, Path(r"C:\Program Files\Go\bin") / exe):
        if cand.is_file():
            return str(cand)
    return None


def check_yaml_syntax(root: Path) -> tuple[bool, str]:
    try:
        import yaml  # noqa: F401
    except ImportError:
        return False, "PyYAML 未安装（python3 -m pip install pyyaml）"

    files = sorted(p for p in (root / "deploy").rglob("*.yaml")
                   if "templates" not in p.parts)  # Helm 模板含 Go template 语法，由 helm lint 校验
    if not files:
        return False, "deploy/ 下未找到 *.yaml"

    import yaml
    bad: list[str] = []
    total = 0
    for f in files:
        try:
            docs = [d for d in yaml.safe_load_all(f.read_text(encoding="utf-8")) if d]
            total += len(docs)
        except yaml.YAMLError as exc:
            bad.append(f"{f.relative_to(root).as_posix()}: {str(exc).splitlines()[0]}")
    if bad:
        return False, f"{len(bad)} 文件解析失败: {flat('; '.join(bad))}"
    return True, f"{len(files)} files / {total} docs OK"


def normalize_go_env(root: Path) -> None:
    """与 CI 对齐 Go 构建环境。

    本仓 go.work 未入库（.gitignore 忽略），CI checkout 上没有它；但开发机会有。
    一旦处于 workspace 模式，`-mod=mod` 会被 Go 直接拒绝
    （"-mod may only be set to readonly or vendor when in workspace mode"）。
    故检测到 go.work 即强制 GOWORK=off，使本地/真机判定与 CI 一致，
    而不是让门禁因"这台机器恰好有 go.work"而红。
    """
    if os.environ.get("GOWORK"):
        return
    probe = root
    for _ in range(6):
        if (probe / "go.work").exists():
            os.environ["GOWORK"] = "off"
            print(f"[note] 检测到 {probe / 'go.work'}：强制 GOWORK=off（与 CI 无 workspace 的环境一致）")
            return
        if probe.parent == probe:
            return
        probe = probe.parent


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="M10 K8s manifests verification")
    ap.add_argument("--kind", action="store_true", help="额外做 kind 真集群验证")
    args = ap.parse_args(argv)

    root = Path(__file__).resolve().parent.parent
    os.chdir(root)
    normalize_go_env(root)
    print("===== M10 K8s manifests verification =====")

    # ---------- 1. kustomize render ----------
    print("\n[1/6] kustomize render")
    ok_k8s = ok_mon = False
    for target, flag in (("deploy/k8s", "k8s"), ("deploy/monitoring", "monitoring")):
        code, out = run(["kubectl", "kustomize", target], timeout=300)
        good = code == 0 and "kind: Deployment" in out
        if flag == "k8s":
            ok_k8s = good
        else:
            ok_mon = good
        if not good:
            print(f"        {target}: code={code} {flat(out, 200)}")
    check("kustomize render (k8s + monitoring)", ok_k8s and ok_mon)

    # ---------- 2. YAML syntax ----------
    print("\n[2/6] YAML syntax")
    ok_yaml, detail = check_yaml_syntax(root)
    check("YAML syntax (all deploy/*.yaml)", ok_yaml, detail)

    # ---------- 3. kubectl dry-run ----------
    print("\n[3/6] kubectl dry-run")
    code, ctx = run(["kubectl", "config", "current-context"], timeout=60)
    if code == 0 and ctx.strip():
        for target, label in (("deploy/k8s", "k8s"), ("deploy/monitoring", "monitoring")):
            c, o = run(["kubectl", "apply", "--dry-run=server", "-k", target, "-o", "name"], timeout=300)
            check(f"kubectl server dry-run ({label})", c == 0, "" if c == 0 else tail(o))
    else:
        check("kubectl server dry-run (no cluster, skipped)", True,
              "(kustomize + YAML checks cover syntax)")

    # ---------- 4. Go services buildable ----------
    print("\n[4/6] Go services buildable")
    go = find_go()
    if not go:
        check("Go services build", False, "go 未找到（设置 GO_BIN，或确认 /usr/local/go/bin 存在）")
    else:
        code, out = run([go, "build", "-mod=mod",
                         "./gateway/tee-infer-service/", "./gateway/embedding-service/"], timeout=900)
        check("Go services build", code == 0, "" if code == 0 else flat(out))

    # ---------- 5. image buildable ----------
    print("\n[5/6] envoy-gateway image buildable")
    code, out = run(["docker", "build", "-q", "-t", "otpmask/envoy-gateway:latest",
                     "-f", "gateway/wasm/otpmask-plugin/Dockerfile.k8s",
                     "gateway/wasm/otpmask-plugin"], timeout=1800)
    check("envoy-gateway image build (wasm bundled)", code == 0, "" if code == 0 else flat(out))

    # ---------- 6. Helm chart ----------
    print("\n[6/6] Helm Chart (otpmask)")
    helm = os.environ.get("HELM_BIN") or shutil.which("helm")
    if helm:
        c1, o1 = run([helm, "lint", "deploy/helm/otpmask", "-f", "deploy/helm/otpmask/ci-values.yaml"], timeout=300)
        c2, o2 = run([helm, "template", "otpmask", "deploy/helm/otpmask",
                      "-f", "deploy/helm/otpmask/ci-values.yaml"], timeout=300)
        # 无值必须失败（required 守卫生效）—— 负向断言，不能"只要失败就算过"
        c3, o3 = run([helm, "template", "otpmask", "deploy/helm/otpmask"], timeout=300)
        check("helm lint + template render (with ci-values)",
              c1 == 0 and c2 == 0 and "kind: Deployment" in o2,
              "" if c1 == 0 and c2 == 0 else tail(o1 + o2))
        # 负向断言：detail 保留报错摘要作为"守卫确实生效"的证据（截短）
        check("helm template without values fails (secret required guard)",
              c3 != 0 and "sigKey" in o3, tail(o3, 160))
    else:
        check("helm lint + template (helm not found, skipped)", True, "(set HELM_BIN)")

    # ---------- 7. kind（可选） ----------
    if args.kind:
        print("\n[7/7] kind cluster")
        c, o = run(["kind", "create", "cluster", "--config", "deploy/kind/kind-config.yaml"], timeout=1200)
        if c == 0:
            run(["kubectl", "apply", "-k", "deploy/k8s"], timeout=300)
            run(["kubectl", "apply", "-k", "deploy/monitoring"], timeout=300)
            import time
            time.sleep(20)
            _c, pods = run(["kubectl", "get", "pods", "-n", "otpmask", "-o",
                            "jsonpath={range .items[*]}{.metadata.name} {.status.phase}{\"\\n\"}{end}"],
                           timeout=300)
            check("kind cluster + deployments ready", "Running" in pods, flat(pods, 400))
        else:
            check("kind cluster create", False, flat(o))

    # ---------- Summary ----------
    n_pass = sum(1 for r in RESULTS if r[1] == "PASS")
    n_fail = sum(1 for r in RESULTS if r[1] == "FAIL")
    print("\n===== Summary =====")
    for name, status, detail in RESULTS:
        print(f"{status:<5} {name} {detail}".rstrip())
    if n_fail == 0:
        print(f"ALL PASSED ({n_pass}/{len(RESULTS)})")
        return 0
    print(f"FAILED: {n_fail} item(s) ({n_pass}/{len(RESULTS)})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
