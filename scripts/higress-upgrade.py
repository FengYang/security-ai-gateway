#!/usr/bin/env python3
"""
higress-upgrade.py —— Higress 版本升级工具链（含 helm 检查 / CRD / 升级 / 等待 / 验证）。

自携带脚本（本地 WSL 运行）：
  python3 higress-upgrade.py                       # 默认升级到 2.2.5
  python3 higress-upgrade.py --version 2.2.5       # 指定目标版本

安全顺序：
  1) 确保 helm CLI 与 higress 仓库（已存在则跳过；幂等）；
  2) 保存当前 release values 到 /root/higress-values.yaml；
  3) 下载并 apply 目标版本 CRD（GitHub 失败自动回退 higress.io）；
  4) helm upgrade --install -f values；
  5) 等待 higress-system Pod 全部 Ready（动态判定，不硬编码 IP）；
  6) 打印镜像版本与 helm release。

注意：升级前请先执行 higress-backup.py。前置 export SSH_PASSWORD。
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import k3s_remote  # noqa: E402

VALUES_PATH = "/root/higress-values.yaml"


def _run(cmd, timeout=300):
    p = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=timeout
    )
    return p.stdout, p.stderr, p.returncode


def local_main(argv):
    k3s_remote.run_script(os.path.abspath(__file__), *argv, timeout=900)


def ensure_helm():
    out, _, rc = _run("command -v helm >/dev/null 2>&1 && helm version --short")
    if rc == 0 and out.strip():
        print(f"helm 已存在: {out.strip()}")
    else:
        print("安装 helm ...")
        out, err, rc = _run(
            "curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 "
            "-o /tmp/get_helm.sh && chmod 700 /tmp/get_helm.sh && /tmp/get_helm.sh"
        )
        if rc != 0:
            print(f"官方脚本失败，改用二进制包: {err.strip()[:200]}")
            out, err, rc = _run(
                "curl -fsSL https://get.helm.sh/helm-v3.16.2-linux-amd64.tar.gz -o /tmp/helm.tar.gz && "
                "tar -xzf /tmp/helm.tar.gz -C /tmp && "
                "cp /tmp/linux-amd64/helm /usr/local/bin/helm && chmod +x /usr/local/bin/helm"
            )
            if rc != 0:
                raise SystemExit(f"helm 安装失败: {err.strip()[:300]}")

    _run("helm repo add higress https://higress.io/helm-charts 2>/dev/null")
    out, _, _ = _run("helm repo update")
    print(f"helm repo update: {out.strip()[:120]}")


def save_values():
    out, err, rc = _run("helm get values higress -n higress-system")
    if rc == 0:
        with open(VALUES_PATH, "w") as f:
            f.write(out)
        print(f"当前 values 已保存: {VALUES_PATH}")
    else:
        # 全新安装或无法读取：确保 -f 目标存在（空文件，使用 chart 默认值）
        open(VALUES_PATH, "a").close()
        print(f"未能读取 release values（{err.strip()[:120]}）；使用空 values: {VALUES_PATH}")


def apply_crds(version):
    dest = f"/tmp/higress-crd-{version}.yaml"
    urls = [
        f"https://github.com/alibaba/higress/releases/download/v{version}/crd.yaml",
        f"https://higress.io/helm-charts/crds/v{version}.yaml",
    ]
    ok = False
    for url in urls:
        _, _, rc = _run(f"curl -fsSL '{url}' -o {dest}")
        if rc == 0:
            print(f"CRD 已下载: {url}")
            ok = True
            break
    if not ok:
        raise SystemExit("CRD 下载失败（两个源均失败），终止升级")

    out, err, rc = _run(f"kubectl apply -f {dest}")
    sys.stdout.write(out)
    if rc != 0:
        raise SystemExit(f"CRD apply 失败，终止升级: {err.strip()[:300]}")


def helm_upgrade(version):
    cmd = (
        f"helm upgrade higress higress/higress --version {version} "
        f"-n higress-system -f {VALUES_PATH} --install"
    )
    out, err, rc = _run(cmd, timeout=300)
    sys.stdout.write(out)
    if rc != 0:
        raise SystemExit(
            f"helm upgrade 失败: {err.strip()[:400]}\n"
            "回滚: helm rollback higress -n higress-system"
        )


def wait_ready(timeout_s=360):
    print("\n等待 higress-system Pod 全部 Ready ...")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        out, _, _ = _run("kubectl get pods -n higress-system --no-headers")
        lines = out.strip().splitlines()
        all_ready = bool(lines)
        for line in lines:
            parts = line.split()
            if len(parts) < 3:
                all_ready = False
                break
            ready_str, status = parts[1], parts[2]
            cur, total = ready_str.split("/")
            if status != "Running" or cur != total:
                all_ready = False
                break
        if all_ready:
            print("所有 Pod Ready")
            return True
        time.sleep(10)
    print("超时：仍有 Pod 未 Ready，请人工排查")
    return False


def remote_main(argv):
    version = "2.2.5"
    if "--version" in argv:
        i = argv.index("--version")
        if i + 1 < len(argv):
            version = argv[i + 1]

    print(f"=== 升级目标版本: {version} ===")
    print("\n--- 升级前状态 ---")
    out, _, _ = _run("kubectl get pods -n higress-system")
    sys.stdout.write(out)

    print("\n=== Step 1: 确保 helm ===")
    ensure_helm()

    print("\n=== Step 2: 保存 values ===")
    save_values()

    print("\n=== Step 3: 应用 CRD ===")
    apply_crds(version)

    print("\n=== Step 4: Helm upgrade ===")
    helm_upgrade(version)

    print("\n=== Step 5: 等待就绪 ===")
    wait_ready()

    print("\n=== 最终状态 ===")
    out, _, _ = _run("kubectl get pods -n higress-system -o wide")
    sys.stdout.write(out)

    print("\n=== 镜像版本 ===")
    out, _, _ = _run(
        "kubectl get deployment -n higress-system "
        "-o jsonpath='{range .items[*]}{.metadata.name}: "
        "{.spec.template.spec.containers[0].image}{\"\\n\"}{end}'"
    )
    sys.stdout.write(out)

    print("=== Helm release ===")
    out, _, _ = _run("helm list -n higress-system")
    sys.stdout.write(out)


if __name__ == "__main__":
    if "--remote" in sys.argv:
        remote_main(sys.argv[1:])
    else:
        local_main(sys.argv[1:])
