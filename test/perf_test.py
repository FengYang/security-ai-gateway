"""
性能测试脚本 - 对比路由决策开启/关闭的性能开销
依赖: pip install paramiko
"""
import paramiko
import time
import json
import os

NODE_IP = "192.168.31.168"
NODE_USER = "root"
NODE_PASS = os.environ.get("SSH_PASSWORD")
if not NODE_PASS:
    raise SystemExit("[FATAL] 环境变量 SSH_PASSWORD 未设置（口令仅经环境变量注入，严禁硬编码/入库）")
GW_POD = "higress-gateway-dc6665557-xhhxc"
GW_PORT = 30000
SIG_KEY_HEX = "3031323334353637383961626364656630313233343536373839616263646566"

LOCAL_BENCH = r"c:\Users\Robin\Desktop\方案\security-ai-gateway\test\benchtool\main.go"
REMOTE_DIR = "/root/perf"
REMOTE_BIN = f"{REMOTE_DIR}/benchtool"


def ssh_exec(client, cmd, timeout=30):
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    return stdout.read().decode().strip()


def build_config(route_enabled):
    cfg = {
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
        "max_stale_seconds": "-1",
    }
    if route_enabled:
        cfg["gateway_core_enabled"] = True
        cfg["route_verify_key"] = SIG_KEY_HEX
    else:
        cfg["gateway_core_enabled"] = False
    return cfg


def apply_config(client, route_enabled, tag):
    cfg = build_config(route_enabled)
    patch = {
        "spec": {
            "defaultConfigDisable": True,
            "failStrategy": "FAIL_CLOSE",
            "matchRules": [{"ingress": ["infer"], "config": cfg}],
            "url": f"http://wasm-files.otpmask.svc.cluster.local/otpmask-v5.wasm?v=perf-{tag}"
        }
    }
    patch_json = json.dumps(patch).replace("'", "'\\''")
    cmd = f"kubectl patch wasmplugin otpmask -n higress-system --type=merge -p '{patch_json}' 2>&1"
    ssh_exec(client, cmd)
    time.sleep(12)  # 等 ECDS 更新生效


def run_bench(client, concurrency=10, duration=10):
    """在节点上跑压测，用网关 Pod IP 访问"""
    # 获取网关 Pod IP
    pod_ip = ssh_exec(client, f"kubectl get pod -n higress-system {GW_POD} -o jsonpath='{{.status.podIP}}'")
    
    cmd = (
        f"{REMOTE_BIN} "
        f"-url http://{pod_ip}:{GW_PORT}/infer "
        f"-c {concurrency} -d {duration} "
        f"-key CHANGE_ME_API_KEY_A "
        f"-tenant tenant-a "
        f"-model qwen-plus"
    )
    result = ssh_exec(client, cmd, timeout=duration + 30)
    return result


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(NODE_IP, username=NODE_USER, password=NODE_PASS, timeout=10)

    # 1. 准备目录和编译压测工具
    ssh_exec(c, f"mkdir -p {REMOTE_DIR}")
    sftp = c.open_sftp()
    sftp.put(LOCAL_BENCH, f"{REMOTE_DIR}/main.go")
    sftp.close()
    print("✅ 上传压测工具源码")

    cmd = (
        f"export PATH=/usr/local/go/bin:$PATH && "
        f"cd {REMOTE_DIR} && "
        f"go build -o benchtool main.go && "
        f"ls -lh benchtool"
    )
    out = ssh_exec(c, cmd, timeout=60)
    print(f"✅ 编译完成: {out}")

    # 2. 基线测试（路由决策关闭）
    print("\n" + "=" * 60)
    print("测试 1: 基线（路由决策关闭）")
    print("=" * 60)
    apply_config(c, route_enabled=False, tag="off")
    print("配置已应用，开始压测...")
    result_off = run_bench(c, concurrency=20, duration=15)
    print(result_off)

    # 3. 路由决策开启测试
    print("\n" + "=" * 60)
    print("测试 2: 路由决策开启")
    print("=" * 60)
    apply_config(c, route_enabled=True, tag="on")
    print("配置已应用，开始压测...")
    result_on = run_bench(c, concurrency=20, duration=15)
    print(result_on)

    # 4. 恢复正常配置
    print("\n恢复正常配置...")
    apply_config(c, route_enabled=True, tag="restore")

    c.close()
    print("\n✅ 性能测试完成")


if __name__ == "__main__":
    main()
