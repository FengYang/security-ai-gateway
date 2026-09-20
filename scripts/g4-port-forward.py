import paramiko
import time

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

    # 看看 higress-gateway pod 里监听什么端口
    pod = "higress-gateway-dc6665557-trptz"
    print(f"=== pod {pod} 监听端口 ===")
    rc, out, _ = run(c, f"kubectl exec -n higress-system {pod} -- ss -tlnp 2>&1 | head -20")
    print(out)

    # 用 kubectl port-forward 在节点上建隧道
    print("\n=== kubectl port-forward ===")
    # 后台启动 port-forward
    run(c, "pkill -f 'kubectl port-forward' 2>/dev/null; sleep 1")
    run(c, f"""
    nohup kubectl port-forward -n higress-system pod/{pod} 18080:80 18443:443 \
      > /opt/og16-g4/port-forward.log 2>&1 &
    echo "PID=$!"
    """)
    time.sleep(3)

    # 测试
    rc, out, _ = run(c, "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/ 2>&1")
    print(f"  18080/: {out}")

    if out.strip() != "000":
        # 获取 API key
        rc, key, _ = run(c, "kubectl get wasmplugin key-auth -n higress-system -o jsonpath='{.spec.defaultConfig.consumers[0].credential}'")
        api_key = key.strip()

        print(f"\n=== 带 API key 打 /v1/infer ===")
        test_body = '{"messages":[{"role":"user","content":"hi"}],"stream":true,"engine_type":"cmaas"}'
        run(c, f"echo '{test_body}' > /tmp/test-body.json")
        rc, out, err = run(c, f"""
        curl -sS -N -X POST http://127.0.0.1:18080/v1/infer \\
          -H 'x-api-key: {api_key}' \\
          -H 'Content-Type: application/json' \\
          -H 'Accept: text/event-stream' \\
          --data-binary @/tmp/test-body.json \\
          --max-time 15 2>&1 | head -60
        """, timeout=25)
        print(f"响应（前 60 行）:")
        print(out[:3000])
        if err.strip():
            print(f"STDERR: {err[:500]}")
    else:
        # 看 port-forward 日志
        rc, out, _ = run(c, "cat /opt/og16-g4/port-forward.log")
        print(f"port-forward 日志: {out[:500]}")

    c.close()


if __name__ == "__main__":
    main()
