"""
混沌测试脚本
通过 SSH 操作 K3S 节点，执行 3 个故障注入场景：
  1. 删 gateway-core Pod → 验证缓存降级
  2. 删 tee-infer Pod → 验证后端故障
  3. 替换错误验签密钥 → 验证 fail-closed 安全边界
依赖: pip install paramiko
"""
import paramiko
import time
import json

# ====== 配置 ======
NODE_IP = "192.168.31.168"
NODE_USER = "root"
NODE_PASS = "yf0537"
GW_POD = "higress-gateway-dc6665557-xhhxc"
GW_PORT = 30000
API_KEY = "CHANGE_ME_API_KEY_A"
SIG_KEY_HEX = "3031323334353637383961626364656630313233343536373839616263646566"
WRONG_KEY_HEX = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
# ==================


def ssh_exec(client, cmd, timeout=10):
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    return stdout.read().decode().strip()


def curl_infer(client, tenant="tenant-a", model="qwen-plus"):
    cmd = (
        f"kubectl exec -n higress-system {GW_POD} -- "
        f"curl -s -o /dev/null -w '%{{http_code}}' "
        f"-H 'X-API-Key: {API_KEY}' "
        f"-H 'X-Tenant-ID: {tenant}' "
        f"-H 'X-Otp-Model: {model}' "
        f"http://127.0.0.1:{GW_PORT}/infer 2>&1"
    )
    return ssh_exec(client, cmd)


def batch_request(client, n=5, interval=1):
    """连续发 n 个请求，返回状态码列表"""
    codes = []
    for i in range(n):
        codes.append(curl_infer(client))
        time.sleep(interval)
    return codes


def scenario1_control_plane_failure(c):
    """场景1: 删除 gateway-core Pod（控制面故障）"""
    print("\n" + "=" * 60)
    print("场景 1: 控制面故障（删 gateway-core Pod）")
    print("预期: 缓存降级，请求正常返回 400")
    print("=" * 60)

    before = curl_infer(c)
    print(f"  故障前: {before}")

    ssh_exec(c, "kubectl delete pod -n otpmask -l app=gateway-core --force --grace-period=0 2>&1", timeout=10)
    time.sleep(3)
    print("  已删除 gateway-core Pod")

    codes = batch_request(c, n=5, interval=1)
    all_ok = all(c == "400" for c in codes)
    print(f"  故障中 5 次: {codes}")
    print(f"  结果: {'✅ 全部正常（缓存降级生效）" if all_ok else "❌ 有失败")

    time.sleep(20)  # 等恢复
    after = curl_infer(c)
    print(f"  恢复后: {after}")
    return all_ok


def scenario2_backend_failure(c):
    """场景2: 删除 tee-infer Pod（后端故障）"""
    print("\n" + "=" * 60)
    print("场景 2: 后端故障（删 tee-infer Pod）")
    print("预期: 请求返回 503（后端不可达）")
    print("=" * 60)

    before = curl_infer(c)
    print(f"  故障前: {before}")

    ssh_exec(c, "kubectl delete pod -n otpmask -l app=tee-infer-service --force --grace-period=0 2>&1", timeout=10)
    time.sleep(3)
    print("  已删除 tee-infer Pod")

    codes = batch_request(c, n=5, interval=1)
    has_503 = any(c == "503" for c in codes)
    print(f"  故障中 5 次: {codes}")
    print(f"  结果: {'✅ 出现 503（后端故障生效）' if has_503 else '⚠️  未出现 503'}")

    time.sleep(15)
    after = curl_infer(c)
    print(f"  恢复后: {after}")
    return has_503


def scenario3_wrong_key(c):
    """场景3: 错误的 route_verify_key（安全边界）"""
    print("\n" + "=" * 60)
    print("场景 3: 验签密钥错误（安全边界）")
    print("预期: 全部 fail-closed (503)")
    print("=" * 60)

    before = curl_infer(c)
    print(f"  故障前: {before}")

    # 用错误密钥 patch WasmPlugin
    config = _build_config(WRONG_KEY_HEX)
    patch = {
        "spec": {
            "defaultConfigDisable": True,
            "failStrategy": "FAIL_CLOSE",
            "matchRules": [{"ingress": ["infer"], "config": config}],
            "url": "http://wasm-files.otpmask.svc.cluster.local/otpmask-v5.wasm?v=chaos-wrong-key"
        }
    }
    patch_json = json.dumps(patch).replace("'", "'\\''")
    ssh_exec(c, f"kubectl patch wasmplugin otpmask -n higress-system --type=merge -p '{patch_json}' 2>&1")
    time.sleep(12)
    print("  已注入错误密钥")

    codes = batch_request(c, n=5, interval=1)
    all_503 = all(c == "503" for c in codes)
    print(f"  错误密钥下 5 次: {codes}")
    print(f"  结果: {'✅ 全部 fail-closed' if all_503 else '⚠️  有请求未被拒绝（可能是 ECDS 热更新渐进式）'}")

    # 恢复
    config = _build_config(SIG_KEY_HEX)
    patch["spec"]["matchRules"] = [{"ingress": ["infer"], "config": config}]
    patch["spec"]["url"] = "http://wasm-files.otpmask.svc.cluster.local/otpmask-v5.wasm?v=chaos-restore"
    patch_json = json.dumps(patch).replace("'", "'\\''")
    ssh_exec(c, f"kubectl patch wasmplugin otpmask -n higress-system --type=merge -p '{patch_json}' 2>&1")
    time.sleep(15)
    after = curl_infer(c)
    print(f"  恢复后: {after}")
    return all_503


def _build_config(route_key):
    return {
        "attest_mode": "quote",
        "attest_token": SIG_KEY_HEX,
        "credential_enabled": False,
        "credential_interval": "300",
        "credential_name": "otpmask-keys",
        "credential_port": "19095",
        "credential_service": "admin-credential.dns",
        "credential_token": "kind-local-credential-token",
        "embedding_port": "18080",
        "embedding_service": "embedding.dns",
        "gateway_core_credential_name": "core-channel",
        "gateway_core_credential_token": "kind-local-core-channel-token-0123456789",
        "gateway_core_port": "8085",
        "gateway_core_service": "gateway-core.dns",
        "gateway_core_token": "d7877a54dfc79b0720ac112fcce05e51",
        "mask_modulus": "4294967296",
        "model": "mock",
        "poll_interval": "10",
        "ratelimit_enabled": False,
        "sig_key": SIG_KEY_HEX,
        "tee_port": "19090",
        "tee_service": "tee-infer.dns",
        "gateway_core_enabled": True,
        "route_verify_key": route_key,
        "max_stale_seconds": "-1",
    }


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(NODE_IP, username=NODE_USER, password=NODE_PASS, timeout=10)

    print("OTPMask 混沌测试")
    print(f"节点: {NODE_IP}")

    results = []
    results.append(scenario1_control_plane_failure(c))
    results.append(scenario2_backend_failure(c))
    results.append(scenario3_wrong_key(c))

    print("\n" + "=" * 60)
    passed = sum(1 for r in results if r)
    print(f"总结: {passed}/{len(results)} 场景通过")
    print("=" * 60)

    c.close()


if __name__ == "__main__":
    main()
