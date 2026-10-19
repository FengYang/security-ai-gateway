#!/usr/bin/env python3
"""G-4 快速冒烟测试：验证新版 wasm + content_filter 支持"""
import os
import paramiko
import time
import json
import re
import sys

HOST = "192.168.31.166"
USER = "root"
PASS = os.environ.get("SSH_PASSWORD")
if not PASS:
    raise SystemExit("[FATAL] 环境变量 SSH_PASSWORD 未设置（口令仅经环境变量注入，严禁硬编码/入库）")


def run(c, cmd, timeout=30):
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    return rc, out, err


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)

    # 1. 获取 API key
    rc, key, _ = run(c, "kubectl get wasmplugin key-auth -n higress-system -o jsonpath='{.spec.defaultConfig.consumers[0].credential}'")
    api_key = key.strip()
    print(f"[1] API key: {api_key[:10]}... (len={len(api_key)})")

    # 2. 检查当前 otpmask 插件 stats（看是否有 output_guard 指标 = og12 新版）
    print("\n[2] 检查 otpmask 插件 output_guard 指标（og12 新版特征）...")
    rc, podname, _ = run(c, "kubectl get pods -n higress-system -l app=higress-gateway --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}'")
    podname = podname.strip()
    print(f"  网关 Pod: {podname}")

    rc, stats, _ = run(c, f"kubectl exec -n higress-system {podname} -- curl -s 'http://127.0.0.1:15000/stats?filter=otpmask_output'")
    stats = stats.strip()
    if stats:
        print(f"  ✅ 找到 output_guard 指标（og12 新版）：")
        for line in stats.strip().split("\n")[:10]:
            print(f"    {line}")
    else:
        print("  ❌ 未找到 output_guard 指标（可能还是 og11 旧版）")

    # 3. 基础冒烟测试（确认网关正常工作）
    print("\n[3] 基础冒烟测试（hostPort 30000）...")
    body = json.dumps({
        "messages": [{"role": "user", "content": "hello"}],
        "stream": True,
        "engine_type": "cmaas"
    })
    run(c, f"cat > /tmp/g4-smoke.json << 'SMOKEEOF'\n{body}\nSMOKEEOF\n")
    rc, out, _ = run(c, f"""
    curl -s -o /dev/null -w 'HTTP %{{http_code}} (size=%{{size_download}})' -X POST http://127.0.0.1:30000/v1/infer \
      -H 'x-api-key: {api_key}' \
      -H 'Content-Type: application/json' \
      -H 'Accept: text/event-stream' \
      --data-binary @/tmp/g4-smoke.json \
      --max-time 15 2>&1
    """, timeout=20)
    print(f"  响应: {out.strip()}")

    # 4. 检查 tee-infer 状态和模式
    print("\n[4] 检查 tee-infer 服务状态...")
    rc, tee_pod, _ = run(c, "kubectl get pods -n otpmask -l app=tee-infer-service --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}'")
    tee_pod = tee_pod.strip()
    print(f"  tee-infer Pod: {tee_pod}")

    rc, tee_metrics, _ = run(c, f"kubectl exec -n otpmask {tee_pod} -- wget -qO- 'http://127.0.0.1:19090/metrics' 2>&1 | grep -E 'otpmask_output_guard_(requests_total|blocked_total|l2_call_total|enforcing)' | head -10")
    print(f"  output guard metrics:")
    print(f"    {tee_metrics.strip() if tee_metrics.strip() else '(无)'}")

    # 5. 检查 tee-infer 是否是 enforcing 模式
    rc, tee_mode, _ = run(c, f"kubectl exec -n otpmask {tee_pod} -- wget -qO- 'http://127.0.0.1:19090/metrics' 2>&1 | grep -i 'enforc' | head -5")
    print(f"  enforcing 相关指标:")
    print(f"    {tee_mode.strip() if tee_mode.strip() else '(无 enforcing 指标)'}")

    c.close()
    print("\n=== 冒烟测试完成 ===")


if __name__ == "__main__":
    main()
