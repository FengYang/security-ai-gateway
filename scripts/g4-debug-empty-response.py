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

    gw_pod = "higress-gateway-dc6665557-trptz"
    pod = "tee-infer-service-75c5b5fcbb-54cds"

    # 再发一次请求，实时抓日志
    rc, key, _ = run(c, "kubectl get wasmplugin key-auth -n higress-system -o jsonpath='{.spec.defaultConfig.consumers[0].credential}'")
    api_key = key.strip()

    # 先看之前那次请求的网关日志
    print("=== Higress 网关最近日志（otpmask 相关）===")
    rc, out, _ = run(c, f"kubectl logs -n higress-system {gw_pod} --tail=50 2>&1 | grep -iE 'otpmask|content_filter|block|error' | tail -20")
    print(out[-2000:] if out.strip() else "(无)")

    # 再看完整的最近 20 行访问日志
    print("\n=== Higress 网关最近 10 条访问日志 ===")
    rc, out, _ = run(c, f"kubectl logs -n higress-system {gw_pod} --tail=50 2>&1 | grep 'response_code' | tail -10")
    lines = [l for l in out.strip().split("\n") if l.strip()]
    for i, l in enumerate(lines):
        # 提取关键字段
        import re
        code_m = re.search(r'"response_code":"(\d+)"', l)
        path_m = re.search(r'"path":"([^"]+)"', l)
        detail_m = re.search(r'"response_code_details":"([^"]+)"', l)
        upstream_m = re.search(r'"upstream_host":"([^"]+)"', l)
        code = code_m.group(1) if code_m else "?"
        path = path_m.group(1) if path_m else "?"
        detail = detail_m.group(1) if detail_m else "?"
        upstream = upstream_m.group(1) if upstream_m else "-"
        print(f"  [{i+1}] {code} {path} | upstream={upstream} | detail={detail[:40]}")

    # 直接从节点 curl tee-infer，绕过 otpmask 插件，看看 tee-infer 返回什么
    # 但是 tee-infer 用的是自定义密封协议，不好直接调
    # 换个思路：看 tee-infer 的完整输出日志
    print(f"\n=== tee-infer 最新日志（最后 30 行）===")
    rc, out, _ = run(c, f"kubectl logs -n otpmask {pod} --tail=30 2>&1")
    print(out[-1500:])

    c.close()


if __name__ == "__main__":
    main()
