#!/usr/bin/env python3
"""
tempo-verify.py —— 验证 Tempo 能接收并取回 trace。

自携带脚本（本地 WSL 运行）：
  python3 tempo-verify.py
  python3 tempo-verify.py --tenant t-smoke-001

行为：
  1) 取 tempo Service 的 ClusterIP；
  2) 经 OTLP HTTP（4318）发送一个 trace ID 已知的测试 span；
  3) 按 trace ID 调用 /api/traces/{id} 核对内容（列出 service 与 span 数）；
  4) 调用 /api/search 回显可检索结果（新写入若仍在 WAL，search 可能延迟，
     以“按 ID 查询成功”为通过主标准）。

前置：export SSH_PASSWORD。
"""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import k3s_remote  # noqa: E402


def _run(cmd, timeout=30):
    p = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=timeout
    )
    return p.stdout, p.stderr, p.returncode


def local_main(argv):
    k3s_remote.run_script(os.path.abspath(__file__), *argv, timeout=120)


def _opt(argv, name, default):
    if name in argv:
        i = argv.index(name)
        if i + 1 < len(argv):
            return argv[i + 1]
    return default


def remote_main(argv):
    tenant = _opt(argv, "--tenant", "t-smoke-001")

    ip_out, _, _ = _run(
        "kubectl get svc tempo -n otpmask -o jsonpath='{.spec.clusterIP}'"
    )
    tempo_ip = ip_out.strip()
    print(f"Tempo ClusterIP: {tempo_ip}")

    trace_id = "0123456789abcdef0123456789abcdef"
    now_ns = str(int(time.time() * 1e9))
    span = {
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    {"key": "service.name",
                     "value": {"stringValue": "verify-test"}},
                    {"key": "tenant.id",
                     "value": {"stringValue": tenant}},
                ]
            },
            "scopeSpans": [{
                "scope": {"name": "test"},
                "spans": [{
                    "name": "verification-span",
                    "spanId": "0123456789abcdef",
                    "traceId": trace_id,
                    "startTimeUnixNano": now_ns,
                    "endTimeUnixNano": str(int(now_ns) + 50_000_000),
                    "kind": 2,
                    "attributes": [
                        {"key": "http.status_code",
                         "value": {"intValue": "200"}},
                        {"key": "http.method",
                         "value": {"stringValue": "GET"}},
                    ],
                }],
            }],
        }]
    }

    print("\n=== 发送测试 span ===")
    out, _, rc = _run(
        f"curl -s -w '\\nHTTP:%{{http_code}}' -X POST "
        f"-H 'Content-Type: application/json' "
        f"http://{tempo_ip}:4318/v1/traces -d '{json.dumps(span)}'"
    )
    print(out.strip()[:200])

    time.sleep(5)

    print(f"\n=== 按 ID 查询 {trace_id} ===")
    out, _, _ = _run(
        f"curl -s 'http://{tempo_ip}:3200/api/traces/{trace_id}'"
    )
    try:
        data = json.loads(out)
        batches = data.get("batches", [])
        found_services = []
        total = 0
        for b in batches:
            svc = "unknown"
            for attr in b.get("resource", {}).get("attributes", []):
                if attr.get("key") == "service.name":
                    svc = attr.get("value", {}).get("stringValue", "?")
            spans = 0
            for ss in b.get("scopeSpans", []):
                spans += len(ss.get("spans", []))
            found_services.append(svc)
            total += spans
        if batches:
            print(f"  通过：{total} span，service={found_services}")
        else:
            raise SystemExit("按 ID 查询未返回批次")
    except SystemExit:
        raise
    except Exception:
        raise SystemExit(f"按 ID 查询失败: {out[:200]}")

    print("\n=== Search（WAL 未刷盘时可能为 0，仅参考）===")
    out, _, _ = _run(f"curl -s 'http://{tempo_ip}:3200/api/search?limit=20'")
    try:
        data = json.loads(out)
        traces = data.get("traces", [])
        print(f"  当前可检索 trace 数: {len(traces)}")
        for t in traces[:5]:
            print(f"    {t.get('rootServiceName','?')}: "
                  f"{t.get('rootTraceName','?')}")
    except Exception:
        print(f"  search 响应: {out[:200]}")

    print("\n结论：Tempo ingest 与按 ID 取回正常；search 受 block 刷盘周期影响。")


if __name__ == "__main__":
    if "--remote" in sys.argv:
        remote_main(sys.argv[1:])
    else:
        local_main(sys.argv[1:])
