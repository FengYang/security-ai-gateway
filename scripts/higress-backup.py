#!/usr/bin/env python3
"""
higress-backup.py —— 升级前完整备份 Higress 配置。

自携带脚本（本地 WSL 运行）：
  python3 higress-backup.py
  python3 higress-backup.py --backup-root /root      # 可选，默认 /root

备份内容：Helm release secret、ConfigMaps、CRD、自定义资源（WasmPlugin/McpBridge 等）、
Deployment、命名空间全量清单。备份目录打印在输出末尾（节点本地路径）。

前置：已 export SSH_PASSWORD；可选 SSH_HOST。
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import k3s_remote  # noqa: E402


def _run(cmd, timeout=60):
    p = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=timeout
    )
    return p.stdout, p.stderr, p.returncode


def local_main(argv):
    k3s_remote.run_script(os.path.abspath(__file__), *argv, timeout=300)


def remote_main(argv):
    backup_root = "/root"
    if "--backup-root" in argv:
        i = argv.index("--backup-root")
        if i + 1 < len(argv):
            backup_root = argv[i + 1]

    backup_dir = f"{backup_root}/higress-backup-{time.strftime('%Y%m%d-%H%M%S')}"
    os.makedirs(backup_dir, exist_ok=True)
    print(f"备份目录: {backup_dir}")

    print("\n=== 1. Helm release secret ===")
    out, _, _ = _run(
        f"kubectl get secret -n higress-system -l owner=helm "
        f"-o yaml > {backup_dir}/helm-release-secrets.yaml 2>&1 && echo OK"
    )
    print(f"  {out.strip()}")

    print("\n=== 2. ConfigMaps ===")
    out, _, _ = _run(
        f"kubectl get configmap -n higress-system "
        f"-o yaml > {backup_dir}/higress-configmaps.yaml 2>&1 && echo OK"
    )
    print(f"  {out.strip()}")
    _run(
        f"kubectl get configmap higress-config -n higress-system "
        f"-o yaml > {backup_dir}/higress-config.yaml"
    )
    print("  higress-config.yaml: saved")

    print("\n=== 3. CRDs ===")
    crds = [
        "http2rpcs.networking.higress.io",
        "mcpbridges.networking.higress.io",
        "wasmplugins.extensions.higress.io",
        "envoyfilters.networking.istio.io",
        "gateways.gateway.networking.k8s.io",
        "httproutes.gateway.networking.k8s.io",
        "backendtlspolicies.gateway.networking.k8s.io",
    ]
    for crd in crds:
        safe = crd.replace(".", "_")
        _, _, rc = _run(
            f"kubectl get crd {crd} -o yaml > {backup_dir}/crd-{safe}.yaml 2>&1"
        )
        print(f"  {crd}: {'OK' if rc == 0 else 'FAILED'}")

    print("\n=== 4. Custom Resources ===")
    resources = [
        ("wasmplugins.extensions.higress.io", "wasmplugins"),
        ("mcpbridges.networking.higress.io", "mcpbridges"),
        ("http2rpcs.networking.higress.io", "http2rpcs"),
        ("envoyfilters.networking.istio.io", "envoyfilters"),
        ("gateways.gateway.networking.k8s.io", "gateways"),
        ("httproutes.gateway.networking.k8s.io", "httproutes"),
    ]
    for res, short in resources:
        _, _, rc = _run(
            f"kubectl get {res} -A -o yaml > {backup_dir}/{short}.yaml 2>&1"
        )
        print(f"  {res}: {'OK' if rc == 0 else 'FAILED'}")

    print("\n=== 5. Deployments ===")
    out, _, _ = _run(
        f"kubectl get deployment -n higress-system "
        f"-o yaml > {backup_dir}/higress-deployments.yaml 2>&1 && echo OK"
    )
    print(f"  {out.strip()}")

    print("\n=== 6. Full namespace dump ===")
    _run(
        f"kubectl get all -n higress-system -o wide > {backup_dir}/all-resources.txt 2>&1"
    )
    print("  all-resources.txt: saved")

    print("\n=== 备份完成 ===")
    out, _, _ = _run(f"ls -lh {backup_dir}/")
    sys.stdout.write(out)
    print(f"\n备份目录（回滚时使用）: {backup_dir}")


if __name__ == "__main__":
    if "--remote" in sys.argv:
        remote_main(sys.argv[1:])
    else:
        local_main(sys.argv[1:])
