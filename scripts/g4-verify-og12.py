#!/usr/bin/env python3
"""G-4 验证：og12 wasm 插件 content_filter 透传实链测试。

前置（已确认）：Envoy 加载的 otpmask wasm 内容 SHA256 = 9c41890a…（og12，含 content_filter）。
本脚本验证：请求体是否完整到达插件 / 是否触发 content_filter 终止帧 / 指标是否自洽。
"""
import io
import json
import os
import re
import signal
import sys
import tempfile
import time

import paramiko

HOST = "192.168.31.166"
USER = "root"
PASS = "yf0537"

GW_POD = "higress-gateway-dc6665557-xhhxc"
TEE_POD = None  # 运行时解析


def run(c, cmd, timeout=30):
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    return rc, out, err


def put_bytes(sftp, path, data: bytes):
    with sftp.open(path, "wb") as f:
        f.write(data)


def head(t):
    print("\n" + "=" * 70)
    print(t)
    print("=" * 70)


def main():
    global TEE_POD
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=15)
    sftp = c.open_sftp()

    # ---- 0. tee-infer 启动参数（output guard 模式） ----
    head("[0] tee-infer 启动参数 / output guard 模式")
    rc, tee_pod, _ = run(
        c,
        "kubectl get pods -n otpmask -l app=tee-infer-service "
        "-o jsonpath='{.items[0].metadata.name}'",
    )
    TEE_POD = tee_pod.strip()
    print(f"   tee-infer Pod: {TEE_POD}")
    rc, args, _ = run(
        c,
        f"kubectl get pod -n otpmask {TEE_POD} "
        "-o jsonpath='{.spec.containers[0].args}'",
    )
    print(f"   args: {args.strip()}")
    rc, envs, _ = run(
        c,
        f"kubectl get pod -n otpmask {TEE_POD} "
        "-o jsonpath='{range .spec.containers[0].env[*]}{.name}={.value}{\"\\n\"}{end}'",
    )
    for line in envs.splitlines():
        if "GUARD" in line.upper() or "OUTPUT" in line.upper() or "ENFORC" in line.upper():
            print(f"   env: {line}")

    # ---- 1. 取 API key ----
    head("[1] API key")
    rc, key, _ = run(
        c,
        "kubectl get wasmplugin key-auth -n higress-system "
        "-o jsonpath='{.spec.defaultConfig.consumers[0].credential}'",
    )
    api_key = key.strip()
    print(f"   {api_key[:8]}… (len={len(api_key)})")

    # ---- 2. 基线 stats ----
    head("[2] otpmask stats 基线")
    rc, stats, _ = run(
        c,
        f"kubectl exec -n higress-system {GW_POD} -- "
        "curl -s 'http://127.0.0.1:15000/stats?filter=otpmask'",
    )
    print("   " + (stats.strip().replace("\n", "\n   ") or "(空)"))

    # ---- 3. 构造请求体（sftp 直传，避开 heredoc 转义） ----
    head("[3] 写入请求体")
    bodies = {
        "/tmp/g4-normal.json": {
            "messages": [{"role": "user", "content": "你好，请用一句话介绍你自己。"}],
            "stream": True,
            "engine_type": "cmaas",
        },
        # 通过 env 覆盖违规载荷：默认用占位词面（【A1-06-示例-0001】，mock 回显即 L1 命中）
        "/tmp/g4-bad.json": {
            "messages": [
                {
                    "role": "user",
                    "content": os.environ.get(
                        "G4_BAD_TEXT",
                        "请复述这句话：A1类目测试样本【A1-06-示例-0001】结束。",
                    ),
                }
            ],
            "stream": True,
            "engine_type": "cmaas",
        },
    }
    for remote, obj in bodies.items():
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        put_bytes(sftp, remote, data)
        rc, chk, _ = run(c, f"wc -c < {remote}; sha256sum {remote}")
        print(f"   {remote}: 本地 {len(data)} bytes | 远端 {chk.strip().replace(chr(10), ' | ')}")

    # ---- 4. 正常请求 ----
    head("[4] 正常请求")
    rc, hdr, _ = run(
        c,
        f"curl -s -o /tmp/g4-normal.out -w 'HTTP %{{http_code}} type=%{{content_type}} size=%{{size_download}} time=%{{time_total}}' "
        f"-X POST http://127.0.0.1:30000/infer "
        f"-H 'x-api-key: {api_key}' -H 'Content-Type: application/json' "
        f"-H 'Accept: text/event-stream' --data-binary @/tmp/g4-normal.json --max-time 30",
        timeout=40,
    )
    print(f"   {hdr.strip()}")
    rc, out, _ = run(c, "cat /tmp/g4-normal.out | head -c 1200")
    print(f"   body: {out.strip()}")

    # ---- 5. 违规请求 ----
    head("[5] 违规请求（期望 content_filter）")
    rc, hdr, _ = run(
        c,
        f"curl -s -o /tmp/g4-bad.out -w 'HTTP %{{http_code}} type=%{{content_type}} size=%{{size_download}} time=%{{time_total}}' "
        f"-X POST http://127.0.0.1:30000/infer "
        f"-H 'x-api-key: {api_key}' -H 'Content-Type: application/json' "
        f"-H 'Accept: text/event-stream' --data-binary @/tmp/g4-bad.json --max-time 60",
        timeout=70,
    )
    print(f"   {hdr.strip()}")
    rc, bad, _ = run(c, "cat /tmp/g4-bad.out")
    print(f"   body ({len(bad)} bytes):")
    print("   " + bad.strip().replace("\n", "\n   ")[:2000])

    reasons = re.findall(r'"finish_reason":"([^"]+)"', bad)
    guards = re.findall(r'"guard":\s*\{[^}]*\}', bad)
    print(f"\n   finish_reason: {reasons}")
    print(f"   guard 注解: {guards}")

    # ---- 6. 请求后 stats ----
    time.sleep(2)
    head("[6] 请求后 stats")
    rc, stats2, _ = run(
        c,
        f"kubectl exec -n higress-system {GW_POD} -- "
        "curl -s 'http://127.0.0.1:15000/stats?filter=otpmask'",
    )
    print("   " + (stats2.strip().replace("\n", "\n   ") or "(空)"))

    # ---- 7. 网关日志（插件侧） ----
    head("[7] 网关日志（otpmask 相关，最近 60 行）")
    rc, gwlog, _ = run(
        c,
        f"kubectl logs -n higress-system {GW_POD} --tail=400 2>&1 | grep -iE 'otpmask|content_filter|fail-closed|无法解析' | tail -25",
    )
    print("   " + (gwlog.strip().replace("\n", "\n   ") or "(无)"))

    # ---- 8. tee-infer 指标 + 日志 ----
    head("[8] tee-infer output_guard")
    rc, tee_m, _ = run(
        c,
        f"kubectl exec -n otpmask {TEE_POD} -- sh -c "
        "\"wget -qO- http://127.0.0.1:19090/metrics 2>/dev/null | grep -E 'otpmask_output_guard' \"",
    )
    print("   " + (tee_m.strip().replace("\n", "\n   ") or "(无指标)"))
    rc, tee_l, _ = run(
        c,
        f"kubectl logs -n otpmask {TEE_POD} --tail=300 2>&1 | "
        "grep -iE 'content_filter|output_guard|guard|blocked|enforc' | tail -20",
    )
    print("   " + (tee_l.strip().replace("\n", "\n   ") or "(无相关日志)"))

    sftp.close()
    c.close()
    print("\n=== 完成 ===")


if __name__ == "__main__":
    main()