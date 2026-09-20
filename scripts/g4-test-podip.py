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

    # 找 higress-gateway pod
    print("=== higress-gateway pods ===")
    rc, out, _ = run(c, "kubectl get pods -n higress-system | grep higress-gateway")
    print(out)

    # 用 pod IP 直接打
    pod_name = [l for l in out.strip().split('\n') if 'Running' in l][0].split()[0]
    print(f"Pod: {pod_name}")

    rc, pod_ip, _ = run(c, f"kubectl get pod -n higress-system {pod_name} -o jsonpath='{{.status.podIP}}'")
    print(f"Pod IP: {pod_ip.strip()}")

    # 直接打 pod IP
    ip = pod_ip.strip()
    print(f"\n=== 直接打 pod IP:80 ===")
    rc, out, _ = run(c, f"curl -s -o /dev/null -w '%{{http_code}}' http://{ip}/ 2>&1")
    print(f"  /: {out}")

    rc, out, _ = run(c, f"curl -s -o /dev/null -w '%{{http_code}}' http://{ip}/v1/infer 2>&1")
    print(f"  /v1/infer: {out}")

    # 获取 API key
    rc, key, _ = run(c, "kubectl get wasmplugin key-auth -n higress-system -o jsonpath='{.spec.defaultConfig.consumers[0].credential}'")
    api_key = key.strip()

    # 带 API key 测试
    print(f"\n=== 带 API key 打 /v1/infer ===")
    test_body = '{"messages":[{"role":"user","content":"hi"}],"stream":true,"engine_type":"cmaas"}'
    run(c, f"echo '{test_body}' > /tmp/test-body.json")
    rc, out, err = run(c, f"""
    curl -sS -N -X POST http://{ip}/v1/infer \
      -H 'x-api-key: {api_key}' \
      -H 'Content-Type: application/json' \
      -H 'Accept: text/event-stream' \
      --data-binary @/tmp/test-body.json \
      --max-time 20 2>&1 | head -50
    """, timeout=30)
    print(f"响应（前 50 行）:")
    print(out[:2000])
    if err.strip():
        print(f"STDERR: {err[:500]}")

    c.close()


if __name__ == "__main__":
    main()
