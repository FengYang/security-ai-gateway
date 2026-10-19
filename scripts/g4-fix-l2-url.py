import os
import paramiko
import time
import json

HOST = "192.168.31.166"
USER = "root"
PASS = os.environ.get("SSH_PASSWORD")
if not PASS:
    raise SystemExit("[FATAL] 环境变量 SSH_PASSWORD 未设置（口令仅经环境变量注入，严禁硬编码/入库）")


def run(c, cmd, timeout=60):
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    return rc, out, err


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)

    # patch deployment: 给 L2 URL 加上 /classify
    print("=== patch tee-infer deployment：L2 URL 加 /classify ===")
    patch = json.dumps({
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "name": "tee-infer-service",
                        "args": [
                            "-sig-key", "$(SIG_KEY)",
                            "-attest-token", "$(ATTEST_TOKEN)",
                            "-output-guard", "enforcing",
                            "-output-guard-policy-dir", "/app/policy",
                            "-output-guard-l2-url", "http://qwen3guard-l2.otpmask:19112/classify",
                            "-output-guard-l2-allowed-cidrs", "192.168.31.166/32,10.43.0.0/16",
                            "-cmaas-url", "$(CMAAS_URL)",
                            "-cmaas-model", "$(CMAAS_MODEL)"
                        ]
                    }]
                }
            }
        }
    })

    rc, out, err = run(c, f"kubectl patch deploy -n otpmask tee-infer-service --type=merge -p '{patch}' 2>&1")
    print(f"  {out.strip()}")
    if err.strip():
        print(f"  err: {err.strip()}")

    # 等待新 pod 启动
    print("\n=== 等待新 pod 启动 ===")
    for i in range(30):
        time.sleep(3)
        rc, out, _ = run(c, "kubectl get pods -n otpmask | grep tee-infer | grep -v Terminating")
        lines = [l for l in out.strip().split("\n") if l.strip()]
        if len(lines) == 1 and "Running" in lines[0] and "1/1" in lines[0]:
            print(f"  第 {i+1} 次检查：pod 已就绪")
            print(f"  {lines[0]}")
            break
        print(f"  第 {i+1} 次检查：{lines[0] if lines else '(none)'}")

    # 验证新参数
    print("\n=== 验证新参数 ===")
    rc, out, _ = run(c, "kubectl get deploy -n otpmask tee-infer-service -o jsonpath='{.spec.template.spec.containers[0].args}' | python3 -c \"import sys,json; args=json.load(sys.stdin); [print(f'  {args[i]} {args[i+1]}') for i in range(0,len(args),2)]\"")
    print(out)

    # 发测试请求验证
    time.sleep(2)
    rc, key, _ = run(c, "kubectl get wasmplugin key-auth -n higress-system -o jsonpath='{.spec.defaultConfig.consumers[0].credential}'")
    api_key = key.strip()

    run(c, """
cat > /tmp/test.json << 'EOF'
{"messages":[{"role":"user","content":"hi"}],"stream":true,"engine_type":"cmaas"}
EOF
""")

    print("\n=== 测试请求（验证 L2 调用成功）===")
    rc, out, _ = run(c, f"""
    curl -sS -N -X POST http://127.0.0.1:18080/v1/infer \
      -H 'x-api-key: {api_key}' \
      -H 'Content-Type: application/json' \
      -H 'Accept: text/event-stream' \
      --data-binary @/tmp/test.json \
      --max-time 15 2>&1 | head -20
    """, timeout=20)
    print(out[:1000])

    # 看 metrics
    time.sleep(1)
    pod_name = ""
    rc, out, _ = run(c, "kubectl get pods -n otpmask | grep tee-infer | grep Running")
    if out.strip():
        pod_name = out.strip().split()[0]

    if pod_name:
        print(f"\n=== L2 调用 metrics（新 pod {pod_name}）===")
        rc, out, _ = run(c, f"kubectl exec -n otpmask {pod_name} -- wget -qO- http://127.0.0.1:19090/metrics 2>&1 | grep -E 'otpmask_output_guard_(requests|l2_call|blocked|degraded)'")
        print(out[:1500])

    c.close()


if __name__ == "__main__":
    main()
