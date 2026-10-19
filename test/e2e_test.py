"""
E2E 功能验证脚本
通过 SSH 操作 K3S 节点，验证 otpmask 插件的核心功能。
依赖: pip install paramiko
"""
import os
import paramiko
import time

# ====== 配置 ======
NODE_IP = "192.168.31.168"
NODE_USER = "root"
NODE_PASS = os.environ.get("SSH_PASSWORD")
if not NODE_PASS:
    raise SystemExit("[FATAL] 环境变量 SSH_PASSWORD 未设置（口令仅经环境变量注入，严禁硬编码/入库）")
GW_POD = "higress-gateway-dc6665557-xhhxc"  # 网关 Pod 名
GW_PORT = 30000  # 容器内 HTTP 端口
API_KEY = "CHANGE_ME_API_KEY_A"
# ==================


def ssh_exec(client, cmd, timeout=10):
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    return stdout.read().decode().strip()


def curl_infer(client, tenant, model, extra_headers=None):
    """通过网关 Pod 内部 curl 发送推理请求"""
    headers = f"-H 'X-API-Key: {API_KEY}' -H 'X-Tenant-ID: {tenant}' -H 'X-Otp-Model: {model}'"
    if extra_headers:
        for k, v in extra_headers.items():
            headers += f" -H '{k}: {v}'"
    cmd = (
        f"kubectl exec -n higress-system {GW_POD} -- "
        f"curl -s -o /dev/null -w '%{{http_code}}' {headers} "
        f"http://127.0.0.1:{GW_PORT}/infer 2>&1"
    )
    return ssh_exec(client, cmd)


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(NODE_IP, username=NODE_USER, password=NODE_PASS, timeout=10)

    print("=" * 60)
    print("E2E 功能验证")
    print("=" * 60)

    tests = [
        ("已知租户+模型 → 路由通过", "tenant-a", "qwen-plus", None, "400"),
        ("未知租户 → fail-closed (503)", "unknown-tenant", "qwen-plus", None, "503"),
        ("无 API Key → 鉴权拒绝 (401)", "tenant-a", "qwen-plus", {"X-API-Key": ""}, "401"),
    ]

    passed = 0
    for name, tenant, model, extra, expected in tests:
        code = curl_infer(c, tenant, model, extra)
        ok = code == expected
        status = "✅ PASS" if ok else "❌ FAIL"
        print(f"  [{status}] {name}")
        print(f"         预期: {expected}, 实际: {code}")
        if ok:
            passed += 1

    print(f"\n结果: {passed}/{len(tests)} 通过")
    c.close()


if __name__ == "__main__":
    main()
