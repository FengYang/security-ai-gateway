import paramiko
import time
import json

HOST = "192.168.31.166"
USER = "root"
PASS = "yf0537"


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

    pod = "higress-gateway-dc6665557-trptz"

    # 杀掉旧的 port-forward
    run(c, "pkill -f 'kubectl port-forward' 2>/dev/null; sleep 1")

    # port-forward 到 30000 端口
    print("=== kubectl port-forward 30000 ===")
    run(c, f"""
    nohup kubectl port-forward -n higress-system pod/{pod} 18080:30000 \
      > /opt/og16-g4/port-forward.log 2>&1 &
    echo "PID=$!"
    """)
    time.sleep(3)

    # 测试连接
    rc, out, _ = run(c, "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/ 2>&1")
    print(f"  /: {out}")

    if out.strip() == "000":
        rc, log, _ = run(c, "tail -5 /opt/og16-g4/port-forward.log")
        print(f"  port-forward 日志: {log.strip()}")
        c.close()
        return

    # 获取 API key
    rc, key, _ = run(c, "kubectl get wasmplugin key-auth -n higress-system -o jsonpath='{.spec.defaultConfig.consumers[0].credential}'")
    api_key = key.strip()
    print(f"  API Key: {api_key[:10]}...")

    # 测试请求（先试简单的，确认能通）
    print("\n=== 测试 /v1/infer（先简单句 warmup）===")
    test_body = json.dumps({
        "messages": [{"role": "user", "content": "hi"}],
        "stream": True,
        "engine_type": "cmaas"
    }, ensure_ascii=False)
    run(c, f"cat > /tmp/test-hi.json << 'EOF'\n{test_body}\nEOF\n")

    rc, out, err = run(c, f"""
    curl -sS -N -X POST http://127.0.0.1:18080/v1/infer \\
      -H 'x-api-key: {api_key}' \\
      -H 'Content-Type: application/json' \\
      -H 'Accept: text/event-stream' \\
      --data-binary @/tmp/test-hi.json \\
      --max-time 20 2>&1 | head -50
    """, timeout=30)
    print(f"响应（前 50 行）:")
    print(out[:3000])
    if err.strip() and "Closing" not in err:
        print(f"STDERR: {err[:300]}")

    # 看 tee-infer 日志
    print("\n=== tee-infer 最新日志 ===")
    rc, logs, _ = run(c, "kubectl logs -n otpmask deploy/tee-infer-service --tail=30 2>&1")
    print(logs[-1500:])

    c.close()


if __name__ == "__main__":
    main()
