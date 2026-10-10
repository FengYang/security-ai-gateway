#!/usr/bin/env python3
"""
higress-tracing.py —— 启用 Higress 原生 OpenTelemetry tracing 并验证 span 发出。

自携带脚本（本地 WSL 运行）：
  python3 higress-tracing.py
  python3 higress-tracing.py --sampling 100 \
      --collector otel-collector.otpmask.svc.cluster.local --collector-port 4317

行为：
  1) 在 higress-config ConfigMap 的“higress”字段写入 tracing（opentelemetry）；
     注意是 higress 字段，不是 mesh.defaultConfig（后者不生效）；
  2) 重启 gateway 并等待 Ready；
  3) 发 N 个请求，核对 Envoy tracing.opentelemetry.spans_sent 增量。

参数（均有默认值）：
  --sampling        入口采样率，默认 100（实测期）；生产按需调低
  --collector       OTel Collector 服务，默认 otel-collector.otpmask.svc.cluster.local
  --collector-port  默认 4317
  --timeout         上报超时 ms，默认 500
  --requests        验证请求数，默认 5

前置：export SSH_PASSWORD。
"""
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import k3s_remote  # noqa: E402


def _run(cmd, timeout=300):
    p = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=timeout
    )
    return p.stdout, p.stderr, p.returncode


def local_main(argv):
    k3s_remote.run_script(os.path.abspath(__file__), *argv, timeout=600)


def _opt(argv, name, default):
    if name in argv:
        i = argv.index(name)
        if i + 1 < len(argv):
            return argv[i + 1]
    return default


def patch_tracing(sampling, collector, port, timeout_ms):
    import yaml

    out, err, rc = _run(
        "kubectl get configmap higress-config -n higress-system -o yaml"
    )
    if rc != 0:
        raise SystemExit(f"获取 higress-config 失败: {err.strip()[:200]}")

    cm = yaml.safe_load(out)
    hig_text = (cm.get("data") or {}).get("higress", "") or ""
    hig = yaml.safe_load(hig_text) or {}
    hig["tracing"] = {
        "enable": True,
        "sampling": int(sampling),
        "timeout": int(timeout_ms),
        "opentelemetry": {
            "service": collector,
            "port": str(port),
        },
    }
    cm["data"]["higress"] = yaml.safe_dump(
        hig, sort_keys=False, default_flow_style=False
    )

    with open("/tmp/higress-config-new.yaml", "w") as f:
        yaml.safe_dump(cm, f, sort_keys=False, default_flow_style=False)

    out, err, rc = _run("kubectl replace -f /tmp/higress-config-new.yaml")
    if rc != 0:
        raise SystemExit(f"ConfigMap 更新失败: {err.strip()[:300]}")
    print("higress.tracing 已写入")


def wait_ready(timeout_s=300):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        out, _, _ = _run("kubectl get pods -n higress-system --no-headers")
        lines = out.strip().splitlines()
        ready = bool(lines)
        for line in lines:
            parts = line.split()
            if len(parts) < 3:
                ready = False
                break
            cur, total = parts[1].split("/")
            if parts[2] != "Running" or cur != total:
                ready = False
                break
        if ready:
            return True
        time.sleep(8)
    return False


def gateway_pod_info():
    pod, _, _ = _run(
        "kubectl get pods -n higress-system -l app=higress-gateway "
        "--field-selector=status.phase=Running "
        "-o jsonpath='{.items[0].metadata.name}'"
    )
    pod = pod.strip()
    ip, _, _ = _run(
        f"kubectl get pod {pod} -n higress-system -o jsonpath='{{.status.podIP}}'"
    )
    return pod, ip.strip()


def spans_sent(pod):
    out, _, _ = _run(
        f"kubectl exec -n higress-system {pod} -- "
        f"curl -s 'http://127.0.0.1:15000/stats?usedonly"
        f"&filter=tracing.opentelemetry.spans_sent'"
    )
    m = re.search(r"spans_sent:\s+(\d+)", out)
    return int(m.group(1)) if m else 0


def remote_main(argv):
    sampling = _opt(argv, "--sampling", "100")
    collector = _opt(
        argv, "--collector", "otel-collector.otpmask.svc.cluster.local"
    )
    port = _opt(argv, "--collector-port", "4317")
    timeout_ms = _opt(argv, "--timeout", "500")
    n_req = int(_opt(argv, "--requests", "5"))

    print("=== Step 1: 写入 higress.tracing ===")
    patch_tracing(sampling, collector, port, timeout_ms)

    print("\n=== Step 2: 重启 gateway ===")
    _run("kubectl rollout restart deployment/higress-gateway -n higress-system")
    if wait_ready():
        print("gateway Ready")
    else:
        raise SystemExit("gateway 重启后超时未 Ready")

    print("\n=== Step 3: 验证 span 增量 ===")
    pod, pod_ip = gateway_pod_info()
    print(f"Gateway: {pod} ({pod_ip})")

    baseline = spans_sent(pod)
    print(f"baseline spans_sent: {baseline}")

    body = json.dumps(
        {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
    )
    for _ in range(n_req):
        _run(
            f"curl -s -o /dev/null --connect-timeout 3 "
            f"-H 'Host: infer' -H 'Content-Type: application/json' "
            f"http://{pod_ip}:30000/v1/chat/completions -d '{body}'",
            timeout=15,
        )

    time.sleep(5)
    after = spans_sent(pod)
    delta = after - baseline
    print(f"after spans_sent: {after} (增量 +{delta})")

    if delta > 0:
        print(f"\n验证通过：Higress OTel tracing 生效，{n_req} 个请求产生 {delta} 个入口 span")
    else:
        raise SystemExit("验证失败：未观测到新 span")


if __name__ == "__main__":
    if "--remote" in sys.argv:
        remote_main(sys.argv[1:])
    else:
        local_main(sys.argv[1:])
