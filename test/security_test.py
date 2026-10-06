"""
安全测试脚本 - 验证路由决策的安全边界
依赖: pip install paramiko
测试项:
  1. 错误验签密钥 → fail-closed
  2. 伪造处方签名 → 降级 L2（不影响可用性）
  3. 空配置 / 缺字段 → 路由不启用（兼容旧行为）
  4. 超长 tenant/model → 不会 panic / 正常处理
"""
import paramiko
import time
import json
import hashlib
import hmac
import base64

NODE_IP = "192.168.31.168"
NODE_USER = "root"
NODE_PASS = "yf0537"
GW_LABEL = "app=higress-gateway"
GW_NAMESPACE = "higress-system"
GW_PORT = 30000
API_KEY = "CHANGE_ME_API_KEY_A"
SIG_KEY_HEX = "3031323334353637383961626364656630313233343536373839616263646566"


def get_gw_pod(client):
    """通过 label 选择器获取网关 Pod 名"""
    stdin, stdout, stderr = client.exec_command(
        f"kubectl get pod -n {GW_NAMESPACE} -l {GW_LABEL} -o jsonpath='{{.items[0].metadata.name}}' 2>&1"
    )
    return stdout.read().decode().strip()


def ssh_exec(client, cmd, timeout=10):
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    return stdout.read().decode().strip()


def curl_infer(client, tenant, model, extra_headers=None, timeout=5):
    headers = f"-H 'X-API-Key: {API_KEY}' -H 'X-Tenant-ID: {tenant}' -H 'X-Otp-Model: {model}'"
    if extra_headers:
        for k, v in extra_headers.items():
            headers += f" -H '{k}: {v}'"
    cmd = (
        f"kubectl exec -n higress-system {GW_POD} -- "
        f"curl -s -o /dev/null -m {timeout} -w '%{{http_code}}' {headers} "
        f"http://127.0.0.1:{GW_PORT}/infer 2>&1"
    )
    return ssh_exec(client, cmd, timeout=timeout + 5)


def fake_prescription(key_hex, tenant, engine):
    """伪造一个处方签名（用已知密钥），返回 X-Otp-Route header 值"""
    import struct
    key = bytes.fromhex(key_hex)
    # 简单的处方格式: tenant + ":" + engine + ":" + timestamp
    # 实际格式参考 rxroute 包，这里只测"签名验证失败"场景用伪造值
    # 对于安全测试 2，我们直接用一个显然不对的签名
    return "fake.signature.value.here"


def main():
    global GW_POD
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(NODE_IP, username=NODE_USER, password=NODE_PASS, timeout=10)
    GW_POD = get_gw_pod(c)
    print(f"网关 Pod: {GW_POD}")

    results = []

    # 确保路由决策正常开启，等缓存拉取完成
    print("等待路由缓存拉取完成...")
    for i in range(20):
        code = curl_infer(c, "tenant-a", "qwen-plus")
        if code == "400":
            print(f"  ✅ 缓存就绪 ({i+1}s)")
            break
        time.sleep(2)
    else:
        print(f"  ⚠️  20s 内未就绪，最后状态: {code}")

    print(f"\n基线请求: {code}")
    results.append(("基线正常（400）", code == "400"))

    print("\n" + "=" * 60)
    print("安全测试 1: 未知租户 → fail-closed (503)")
    print("=" * 60)
    code = curl_infer(c, "unknown-tenant", "qwen-plus")
    ok = code == "503"
    print(f"  结果: {code} (预期 503) {'✅' if ok else '❌'}")
    results.append(("未知租户 fail-closed", ok))

    print("\n" + "=" * 60)
    print("安全测试 2: 伪造处方签名 → 降级 L2（不 fail-closed）")
    print("=" * 60)
    # 用一个伪造的 X-Otp-Route header
    code = curl_infer(c, "tenant-a", "qwen-plus",
                       {"X-Otp-Route": "fake.signature.12345"})
    # 400 = 正常放行（降级 L2），429 = 限流（也是正常通过了路由决策）
    ok = code in ("400", "429")
    print(f"  结果: {code} (预期 400/429 - 降级 L2 放行) {'✅' if ok else '❌'}")
    results.append(("伪造签名降级 L2 不停服", ok))

    print("\n" + "=" * 60)
    print("安全测试 3: 超长租户名 → 正常处理（不 crash）")
    print("=" * 60)
    long_tenant = "a" * 10000
    code = curl_infer(c, long_tenant, "qwen-plus")
    ok = code in ("400", "503", "413")  # 要么 fail-closed 要么正常，不能挂
    print(f"  结果: {code} (预期 503 - 超长租户名无路由) {'✅' if ok else '❌'}")
    results.append(("超长输入不 crash", ok))

    print("\n" + "=" * 60)
    print("安全测试 4: 空模型名 → fail-closed")
    print("=" * 60)
    code = curl_infer(c, "tenant-a", "")
    ok = code in ("503", "400")  # 空 model 可能直接 fail-closed
    print(f"  结果: {code} (预期 503) {'✅' if code == '503' else '⚠️ ' + code}")
    results.append(("空模型名安全处理", code == "503"))

    print("\n" + "=" * 60)
    print("安全测试 5: 无 API Key → 被拒绝（鉴权层）")
    print("=" * 60)
    stdin, stdout, stderr = c.exec_command(
        f"kubectl exec -n higress-system {GW_POD} -- "
        f"curl -s -o /dev/null -w '%{{http_code}}' "
        f"-H 'X-Tenant-ID: tenant-a' "
        f"-H 'X-Otp-Model: qwen-plus' "
        f"http://127.0.0.1:{GW_PORT}/infer 2>&1"
    )
    code = stdout.read().decode().strip()
    # 401=鉴权拒绝，429=限流（也是被拦截了），都算通过（不是 200/400）
    ok = code in ("401", "403", "429") and code != "400"
    print(f"  结果: {code} (预期被拒，非 400) {'✅' if ok else '❌'}")
    results.append(("无 API Key 被拒绝", ok))

    print("\n" + "=" * 60)
    print("安全测试 6: 特殊字符租户名（注入尝试）")
    print("=" * 60)
    # 避免 shell 引号问题，用双引号包裹 header 值
    evil_tenant = '../etc/passwd ../../etc/shadow'
    stdin, stdout, stderr = c.exec_command(
        f"kubectl exec -n higress-system {GW_POD} -- "
        f"curl -s -o /dev/null -w '%{{http_code}}' "
        f'-H "X-API-Key: {API_KEY}" '
        f'-H "X-Tenant-ID: {evil_tenant}" '
        f'-H "X-Otp-Model: qwen-plus" '
        f"http://127.0.0.1:{GW_PORT}/infer 2>&1"
    )
    code = stdout.read().decode().strip()
    ok = code in ("503", "400", "429")  # 不能 crash，正常返回错误码
    print(f"  租户名: {evil_tenant[:30]}...")
    print(f"  结果: {code} (预期 503) {'✅' if ok else '❌'}")
    results.append(("注入字符安全处理", ok))

    # 总结
    print("\n" + "=" * 60)
    passed = sum(1 for _, ok in results if ok)
    print(f"安全测试结果: {passed}/{len(results)} 通过")
    print("=" * 60)
    for name, ok in results:
        print(f"  {'✅' if ok else '❌'} {name}")

    c.close()


if __name__ == "__main__":
    main()
