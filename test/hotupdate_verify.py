"""
WasmPlugin 配置热更新验证脚本（验证 tick 循环在热更新后仍能自愈）

背景（2026-10-12 集群实测 + wasm-go v1.1.2 SDK 源码取证）：
  SDK 的 CommonPluginCtx.OnPluginStart 每次执行（含 ECDS 配置热更新产生的新插件上下文）
  都会先把全局 tick 注册表清空（plugin_wrapper.go: `globalOnTickFuncs = nil`），
  随后由 parseConfig 重新 RegisterTickFunc。
  若插件用 sync.Once 守卫注册，热更新后 Once 已触发 ⇒ 不再注册 ⇒ 新上下文零 tick
  ⇒ 路由表周期拉取永久停止、内存缓存不再回填 ⇒ 请求持续 fail-closed「无可用路由」。

本脚本以「请求结果」为探针（不依赖 wasm info 日志，因默认日志级别为 warning）：
  1) 前置：热更新前探针必须为 200（否则说明环境本身不健康，先排查）；
  2) 对 WasmPlugin config 做真实热更新（改一个无害键，且值确有变化以触发 ECDS 下发）；
  3) 在退避窗口内轮询探针，观察是否自愈（期望修复后 <1 个 poll 周期即恢复）；
  4) 恢复原值（再一次热更新）并复验。
任意一轮未在窗口内自愈 ⇒ 退出码 1，并打印 fail-closed 证据日志。

依赖: pip install paramiko
用法:
  python hotupdate_verify.py
  python hotupdate_verify.py --rounds 5 --deadline 40 --interval 3
  python hotupdate_verify.py --key poll_interval --value 15
退出码: 0=通过  1=失败
"""
import os
import argparse
import base64
import json
import sys
import time

import paramiko

# ====== 配置（与 test/deploy_wasm.py 等既有脚本一致）======
NODE_IP = "192.168.31.168"
NODE_USER = "root"
NODE_PASS = os.environ.get("SSH_PASSWORD")
if not NODE_PASS:
    raise SystemExit("[FATAL] 环境变量 SSH_PASSWORD 未设置（口令仅经环境变量注入，严禁硬编码/入库）")

NAMESPACE = "higress-system"
PLUGIN_NAME = "otpmask"
GW_URL = "http://192.168.31.168:30000/infer"
API_KEY = "CHANGE_ME_API_KEY_A"
TENANT = "tenant-a"     # 需命中路由表条目
MODEL = "qwen-plus"     # 需命中路由表条目
# ========================================================


def _exec(client, cmd, timeout=30):
    """执行远端命令，返回 (stdout, stderr)。"""
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    return out, err


def get_gateway_pod(client):
    """取当前 Running 的 higress-gateway pod 名。"""
    out, _ = _exec(
        client,
        f"kubectl -n {NAMESPACE} get pods -l app=higress-gateway "
        f"--field-selector=status.phase=Running -o jsonpath='{{.items[0].metadata.name}}'",
    )
    if not out:
        raise RuntimeError("未找到 Running 的 higress-gateway pod")
    return out


def get_config_value(client, key):
    """读取 WasmPlugin matchRules[0].config.<key>。"""
    out, _ = _exec(
        client,
        f"kubectl -n {NAMESPACE} get wasmplugin {PLUGIN_NAME} "
        f"-o jsonpath='{{.spec.matchRules[0].config.{key}}}'",
    )
    return out


def patch_config_value(client, key, value):
    """JSON patch 修改 config.<key>（值以字符串写入，与 CR 既有口径一致）。"""
    patch = json.dumps(
        [{"op": "replace", "path": f"/spec/matchRules/0/config/{key}", "value": str(value)}]
    )
    return _exec(
        client,
        f"kubectl -n {NAMESPACE} patch wasmplugin {PLUGIN_NAME} --type=json -p '{patch}' 2>&1",
    )


def probe(client):
    """发一次 /infer 探针，返回 HTTP 状态码。

    请求体经 base64 传输（规避 shell 引号/转义问题）；curl 在节点侧执行，
    直接打网关 NodeIP:30000。返回码含义：200=命中路由且链路正常；
    503 且插件日志为「无可用路由」= 路由缓存未回填（本脚本要捕获的回归）。
    """
    body = json.dumps({"model": MODEL, "messages": [{"role": "user", "content": "hotupdate-probe"}], "stream": False})
    payload = base64.b64encode(body.encode()).decode()
    cmd = (
        f"sh -c 'echo {payload} | base64 -d > /tmp/hu_req.json; "
        f"curl -s -o /dev/null -w \"%{{http_code}}\" --max-time 15 -X POST {GW_URL} "
        f"-H \"Content-Type: application/json\" -H \"x-api-key: {API_KEY}\" "
        f"-H \"X-Tenant-ID: {TENANT}\" -H \"X-Otp-Model: {MODEL}\" --data-binary @/tmp/hu_req.json'"
    )
    out, _ = _exec(client, cmd, timeout=25)
    return out.strip().splitlines()[-1] if out.strip() else "000"


def fail_closed_evidence(client, pod, since=60):
    """取最近 fail-closed 日志行（失败时的证据）。"""
    out, _ = _exec(
        client,
        f"kubectl -n {NAMESPACE} logs {pod} -c higress-gateway --since={since}s 2>&1 "
        f"| grep 'otpmask-plugin' | grep 'fail-closed' | tail -3",
    )
    return out


def wait_recover(client, pod, interval, deadline):
    """在 deadline 秒内轮询探针，返回 (是否恢复, 首次恢复耗时秒, 末次状态码)。"""
    start = time.time()
    last = None
    while time.time() - start < deadline:
        code = probe(client)
        last = code
        if code == "200":
            return True, round(time.time() - start, 1), code
        # 429（限流）视为环境噪声，继续重试
        time.sleep(interval)
    return False, None, last


def one_round(client, pod, key, new_value, interval, deadline, tag):
    """执行一轮：热更新 -> 观察自愈。返回 (ok, 详情)。"""
    print(f"\n--- 轮次 {tag}: config.{key} -> {new_value} ---")
    out, err = patch_config_value(client, key, new_value)
    if "patched" not in (out + err).lower():
        return False, f"patch 失败: {out or err}"
    actual = get_config_value(client, key)
    if actual != str(new_value):
        return False, f"CR 中值未变更（{actual}），未触发 ECDS 下发"
    ok, cost, last = wait_recover(client, pod, interval, deadline)
    if ok:
        print(f"  ✅ 热更新后 {cost}s 内自愈（末次 HTTP {last}）")
        return True, f"recovered in {cost}s"
    print(f"  ❌ 窗口 {deadline}s 内未自愈（末次 HTTP {last}）")
    ev = fail_closed_evidence(client, pod)
    print(f"  fail-closed 证据:\n{ev}" if ev else "  (无 fail-closed 日志)")
    return False, f"not recovered (last={last})"


def main():
    parser = argparse.ArgumentParser(description="WasmPlugin 配置热更新（tick 自愈）验证")
    parser.add_argument("--rounds", type=int, default=3, help="热更新轮数（默认 3）")
    parser.add_argument("--interval", type=int, default=3, help="探针轮询间隔秒（默认 3）")
    parser.add_argument("--deadline", type=int, default=30, help="单轮自愈窗口秒（默认 30）")
    parser.add_argument("--key", default="poll_interval", help="用于触发热更新的无害配置键（默认 poll_interval）")
    parser.add_argument("--value", default=None, help="热更新目标值；缺省则在原值基础上 +1")
    args = parser.parse_args()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(NODE_IP, username=NODE_USER, password=NODE_PASS, timeout=10)

    results = []
    original = None
    try:
        pod = get_gateway_pod(client)
        print(f"网关 pod: {pod}")

        # 前置检查：热更新前必须为 200
        code = probe(client)
        print(f"前置探针: HTTP {code}")
        if code != "200":
            print("❌ 前置条件不满足：热更新前探针非 200（环境本身不健康，请先排查）")
            print(fail_closed_evidence(client, pod) or "(无 fail-closed 日志)")
            return 1

        original = get_config_value(client, args.key)
        if original == "":
            print(f"❌ 配置键 {args.key} 不存在，无法用于触发热更新")
            return 1
        print(f"原始 config.{args.key} = {original}")

        # 交替取值，确保每次都真实变更（同值 patch 不会触发下发）
        try:
            base = int(original)
        except ValueError:
            base = None

        for r in range(1, args.rounds + 1):
            if args.value is not None:
                new_value = args.value
            else:
                new_value = str(base + r) if base is not None else (original + "_hot")
            ok, detail = one_round(client, pod, args.key, new_value, args.interval, args.deadline, r)
            results.append((r, new_value, ok, detail))

            # 每轮结束恢复原值（再次热更新），并复验恢复后的健康度
            patch_config_value(client, args.key, original)
            ok_restore, cost, last = wait_recover(client, pod, args.interval, args.deadline)
            results.append((f"{r}-restore", original, ok_restore, f"recovered in {cost}s" if ok_restore else f"not recovered (last={last})"))
            print(f"  恢复原值 {original}: {'✅' if ok_restore else '❌'}")

    finally:
        # 兜底恢复原值，避免污染环境
        if original:
            try:
                patch_config_value(client, args.key, original)
            except Exception:
                pass
        client.close()

    print("\n===== 汇总 =====")
    all_ok = True
    for tag, val, ok, detail in results:
        print(f"  {'✅' if ok else '❌'} 轮次 {tag} -> {val}: {detail}")
        all_ok = all_ok and ok
    print("结果:", "PASS" if all_ok else "FAIL")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
