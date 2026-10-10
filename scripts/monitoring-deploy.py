#!/usr/bin/env python3
"""
monitoring-deploy.py —— 一键部署监控栈（Tempo / OTel Collector / Prometheus / Grafana 等）。

自携带脚本（本地 WSL 运行，自动上传到 K3S 节点执行）：
  python3 monitoring-deploy.py

行为：
  - 把仓库 deploy/monitoring 清单目录随脚本打包上传；
  - 节点上执行 kubectl apply -k <清单目录>；
  - 回显 otpmask 命名空间 Pod 状态。

前置：已 export SSH_PASSWORD（远程登录口令）；可选 SSH_HOST。
"""
import os
import subprocess
import sys

# 保证本地与远程（同目录）都能 import 共享助手
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import k3s_remote  # noqa: E402

NAMESPACE = "otpmask"


def _run(cmd, timeout=300):
    p = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=timeout
    )
    return p.stdout, p.stderr, p.returncode


def local_main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    bundle = os.path.join(repo_root, "deploy", "monitoring")
    if not os.path.isdir(bundle):
        raise SystemExit(f"未找到监控清单目录: {bundle}")
    print(f"上传监控清单并部署: {bundle}")
    k3s_remote.run_script(os.path.abspath(__file__), bundle_dir=bundle, timeout=300)


def remote_main(_argv):
    bundle = os.environ.get("K3S_BUNDLE_DIR", "")
    if not bundle:
        raise SystemExit("远程模式缺少 K3S_BUNDLE_DIR")

    print(f"=== kubectl apply -k {bundle} ===")
    out, err, rc = _run(f"kubectl apply -k '{bundle}'")
    sys.stdout.write(out)
    if err.strip():
        sys.stdout.write(err)

    print(f"\n=== {NAMESPACE} 命名空间 Pod 状态 ===")
    out, _, _ = _run(f"kubectl get pods -n {NAMESPACE}")
    sys.stdout.write(out)


if __name__ == "__main__":
    if "--remote" in sys.argv:
        remote_main(sys.argv[1:])
    else:
        local_main()
