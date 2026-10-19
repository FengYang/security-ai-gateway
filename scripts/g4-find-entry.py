import os
import paramiko

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

    # 试试不同入口
    print("=== 测试 NodePort 31768 ===")
    rc, out, _ = run(c, "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:31768/v1/infer 2>&1")
    print(f"  /v1/infer: {out}")

    rc, out, _ = run(c, "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:31768/infer 2>&1")
    print(f"  /infer: {out}")

    # 用 host 头
    print("\n=== 带 Host 头 ===")
    rc, out, _ = run(c, "curl -s -o /dev/null -w '%{http_code}' -H 'Host: infer' http://127.0.0.1:31768/v1/infer 2>&1")
    print(f"  Host: infer: {out}")

    # 默认 ingress 是什么
    print("\n=== 默认 ingress ===")
    rc, out, _ = run(c, "curl -s http://127.0.0.1:31768/ 2>&1 | head -10")
    print(out[:500])

    # 用 key-auth 测试，看有没有到插件层
    print("\n=== 带 x-api-key 测试 ===")
    rc, out, _ = run(c, "curl -s -o /dev/null -w '%{http_code}' -H 'x-api-key: CHANGE_ME_INVALID_KEY' http://127.0.0.1:31768/v1/infer 2>&1")
    print(f"  401/403 说明到了 key-auth 插件: {out}")

    # 试试正确的 api key
    rc, key, _ = run(c, "kubectl get wasmplugin key-auth -n higress-system -o jsonpath='{.spec.defaultConfig.consumers[0].credential}'")
    print(f"  api key: {key[:15]}...")
    rc, out, _ = run(c, f"curl -s -o /dev/null -w '%{{http_code}}' -H 'x-api-key: {key.strip()}' http://127.0.0.1:31768/v1/infer 2>&1")
    print(f"  正确 key: {out}")

    c.close()


if __name__ == "__main__":
    main()
