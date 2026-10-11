#!/usr/bin/env python3
"""
higress-mcp.py —— 启用 / 回滚 Higress 原生 MCP Server（`higress-config` 的 `mcpServer` 段）。

自携带脚本（本地 WSL/Linux 运行；沿用 k3s_remote 上传执行）：
  python3 scripts/higress-mcp.py --profile native
  python3 scripts/higress-mcp.py --profile native --dry-run
  python3 scripts/higress-mcp.py --rollback

行为（--profile native，对应"情况① 客户自建可信内网"）：
  1) 前置校验：Redis 服务与端点可达（若指向集群内 Redis）；
  2) **合并**（非覆盖）写入 `data.higress.mcpServer`（保留 tracing 等既有键）；
  3) 滚动重启 gateway 并等待 Ready；
  4) 冒烟：断言 `mcpServer.enable=true` 已加载 + 探测 MCP 入口（信息性）。

`--profile secure`（情况② 客户不信任基础设施）**尚未实现**：依赖 F-9（段① 不透明载荷）
与 F-10（TEE 内 MCP 协议层），属方案 P2 阶段——本脚本遇 secure 明确报错退出，不静默降级。

参数：
  --profile native|secure  必填（secure 暂未实现）
  --dry-run                只打印将要写入的 mcpServer 段与差异，不做任何变更
  --rollback               删除 `mcpServer` 键并重启（等价"一键关闭"）
  --redis-address          默认 redis-ratelimit.otpmask.svc.cluster.local:6379（方案 §4.3 R1）
                           R2（官方 helm enableRedis）改为 redis-stack-server.higress-system.svc.cluster.local:6379
  --sse-suffix             MCP 客户端 SSE 后缀，默认 /sse

前置：export SSH_PASSWORD（严禁硬编码）。
依据：《GA-Higress-MCP接入与打通-技术实现方案》v1.5 §4.1 / §4.3 / §8。
注意：`higress-config` 的 `higress` 字段还含 tracing 等**运行期追加**内容，故本脚本只
      **合并/删除 `mcpServer` 键**，绝不以整份 ConfigMap 覆盖（防丢 tracing）。
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import k3s_remote  # noqa: E402

CM_NAME = "higress-config"
CM_NS = "higress-system"
DEFAULT_REDIS = "redis-ratelimit.otpmask.svc.cluster.local:6379"
REDIS_SVC_NS = "otpmask"
REDIS_SVC_NAME = "redis-ratelimit"
GW_PORT = "30000"


def _run(cmd, timeout=300):
    import subprocess

    p = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=timeout
    )
    return p.stdout, p.stderr, p.returncode


def local_main(argv):
    k3s_remote.run_script(os.path.abspath(__file__), *argv, timeout=900)


def _opt(argv, name, default=None):
    if name in argv:
        i = argv.index(name)
        if i + 1 < len(argv):
            return argv[i + 1]
    return default


# --------------------------------------------------------------------------- #
# 配置读写（合并语义，绝不整份覆盖）
# --------------------------------------------------------------------------- #
def _read_higress():
    """返回 (完整 cm dict, data.higress 解析后的 dict)。"""
    import yaml

    out, err, rc = _run(f"kubectl get configmap {CM_NAME} -n {CM_NS} -o yaml")
    if rc != 0:
        raise SystemExit(f"获取 {CM_NAME} 失败: {err.strip()[:200]}")
    cm = yaml.safe_load(out) or {}
    data = cm.setdefault("data", {})
    hig_text = data.get("higress") or ""
    hig = yaml.safe_load(hig_text) or {}
    if not isinstance(hig, dict):
        raise SystemExit("higress 字段不是 YAML 映射，拒绝改写")
    return cm, hig


def _apply_higress(cm, hig):
    import yaml

    cm["data"]["higress"] = yaml.safe_dump(
        hig, sort_keys=False, default_flow_style=False, allow_unicode=True
    )
    tmp = "/tmp/higress-config-mcp.yaml"
    with open(tmp, "w") as f:
        yaml.safe_dump(cm, f, sort_keys=False, default_flow_style=False, allow_unicode=True)
    out, err, rc = _run(f"kubectl replace -f {tmp}")
    if rc != 0:
        raise SystemExit(f"ConfigMap 更新失败: {err.strip()[:300]}")


# --------------------------------------------------------------------------- #
# 步骤
# --------------------------------------------------------------------------- #
def check_redis(addr):
    """基础可达性：Redis Service 有端点 + Redis PING 通（不覆盖跨命名空间实测）。"""
    host_port = addr.split("@")[-1]
    host = host_port.rsplit(":", 1)[0]
    print(f"-- Redis 目标: {addr}")
    if host.startswith("redis-ratelimit"):
        out, _, _ = _run(
            f"kubectl get endpoints {REDIS_SVC_NAME} -n {REDIS_SVC_NS} "
            "-o jsonpath='{.subsets[*].addresses[*].ip}'"
        )
        if not out.strip():
            raise SystemExit(
                f"Redis 端点为空：{REDIS_SVC_NS}/{REDIS_SVC_NAME}（请先确认 Redis 就绪）"
            )
        print(f"   Service 端点 OK: {out.strip()}")
        pod, _, _ = _run(
            f"kubectl get pods -n {REDIS_SVC_NS} -l app={REDIS_SVC_NAME} "
            "--field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}'"
        )
        if pod.strip():
            pong, _, _ = _run(
                f"kubectl exec -n {REDIS_SVC_NS} {pod.strip()} -- redis-cli PING"
            )
            if "PONG" in pong:
                print("   容器内 PING -> PONG")
            else:
                print(f"   [警告] redis-cli PING 异常: {pong.strip()[:80]}")
    else:
        print("   [跳过] 非集群内默认 Redis（R2 形态）；请自行确认可达性")


def write_mcp_server(redis_addr, sse_suffix, dry_run):
    cm, hig = _read_higress()
    existed = "mcpServer" in hig
    hig["mcpServer"] = {
        "enable": True,
        "sse_path_suffix": sse_suffix,
        "redis": {"address": redis_addr, "username": "", "password": "", "db": 0},
        # 官方未给出 match_list 语义（方案 U-6）→ 保持空，不臆测
        "match_list": [],
        "servers": [],
    }
    import yaml

    frag = yaml.safe_dump(
        {"mcpServer": hig["mcpServer"]}, sort_keys=False, default_flow_style=False
    )
    print(f"-- 将写入的 mcpServer 段（现有同名键: {'是' if existed else '否'}）：")
    for line in frag.rstrip().splitlines():
        print(f"     {line}")
    if dry_run:
        print("-- [dry-run] 未做任何变更")
        return False
    _apply_higress(cm, hig)
    print("-- 已合并写入 data.higress.mcpServer（其余键保留）")
    return True


def rollback(dry_run):
    cm, hig = _read_higress()
    if "mcpServer" not in hig:
        print("-- 未发现 mcpServer 键，无需回滚")
        return False
    print("-- 将删除 data.higress.mcpServer 键（其余键保留）")
    if dry_run:
        print("-- [dry-run] 未做任何变更")
        return False
    del hig["mcpServer"]
    _apply_higress(cm, hig)
    print("-- 已删除 mcpServer 键")
    return True


def restart_gateway():
    print("\n== 滚动重启 higress-gateway ==")
    _run(f"kubectl rollout restart deployment/higress-gateway -n {CM_NS}")
    if wait_ready():
        print("   gateway Ready")
        return True
    raise SystemExit("gateway 重启后超时未 Ready")


def wait_ready(timeout_s=300):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        out, _, _ = _run(
            f"kubectl get pods -n {CM_NS} -l app=higress-gateway "
            "--field-selector=status.phase=Running --no-headers"
        )
        lines = [l for l in out.strip().splitlines() if l.strip()]
        if lines:
            ok = True
            for line in lines:
                parts = line.split()
                if len(parts) < 3:
                    ok = False
                    break
                cur, total = parts[1].split("/")
                if parts[2] != "Running" or cur != total:
                    ok = False
                    break
            if ok:
                return True
        time.sleep(8)
    return False


def smoke(sse_suffix):
    """冒烟：① 断言配置已加载；② 探测 MCP 入口（信息性，配合方案 U-4）。"""
    print("\n== 冒烟 ==")
    cm, hig = _read_higress()
    ms = hig.get("mcpServer") or {}
    assert ms.get("enable") is True, "mcpServer.enable 未生效"
    assert ms.get("sse_path_suffix") == sse_suffix, "sse_path_suffix 不符"
    print("   ① 配置断言 OK（enable=true）")

    pod, _, _ = _run(
        f"kubectl get pods -n {CM_NS} -l app=higress-gateway "
        "--field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}'"
    )
    pod = pod.strip()
    ip, _, _ = _run(f"kubectl get pod {pod} -n {CM_NS} -o jsonpath='{{.status.podIP}}'")
    ip = ip.strip()
    code, _, _ = _run(
        f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 3 "
        f"-H 'Accept: text/event-stream' "
        f"http://{ip}:{GW_PORT}/mcp-servers/__probe__{sse_suffix}",
        timeout=15,
    )
    print(f"   ② 探测 /mcp-servers/__probe__{sse_suffix} -> HTTP {code.strip()}")
    print("      [说明] 该探测仅验证 MCP 入口是否**已挂载**；完整握手需先注册 MCP 服务"
          "（方案 §4.5 / F-2，且受 U-4 约束）。404 = 可能由内置路由未承载该前缀（需 U-4 复核）。")


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
def remote_main(argv):
    profile = _opt(argv, "--profile")
    dry_run = "--dry-run" in argv
    do_rollback = "--rollback" in argv
    redis_addr = _opt(argv, "--redis-address", DEFAULT_REDIS)
    sse_suffix = _opt(argv, "--sse-suffix", "/sse")

    if do_rollback:
        changed = rollback(dry_run)
        if changed:
            restart_gateway()
            cm, hig = _read_higress()
            assert "mcpServer" not in hig, "回滚后 mcpServer 仍存在"
            print("\n回滚完成：mcpServer 已移除并重启生效")
        return

    if not profile:
        raise SystemExit("用法：--profile native|secure（或 --rollback）")
    if profile == "secure":
        raise SystemExit(
            "profile=secure（情况② 客户不信任基础设施）**尚未实现**：依赖 F-9（段① 不透明载荷）"
            "与 F-10（TEE 内 MCP 协议层），属方案 P2 阶段。\n"
            "本次 P1 仅交付 native；请勿在未实现时启用，以免产生「看似配好、实则无密态」的误判。"
        )
    if profile != "native":
        raise SystemExit(f"未知 profile: {profile}（仅支持 native）")

    print("=== Step 1: Redis 前置校验 ===")
    check_redis(redis_addr)

    print("\n=== Step 2: 合并写入 mcpServer 段 ===")
    changed = write_mcp_server(redis_addr, sse_suffix, dry_run)
    if not changed:
        print("\n[dry-run] 结束（未变更）")
        return

    print("\n=== Step 3: 重启 gateway ===")
    restart_gateway()

    print("\n=== Step 4: 冒烟 ===")
    smoke(sse_suffix)

    print("\n完成：MCP Server（native / 情况①）已启用。"
          "注意：完整 MCP 握手需注册 MCP 服务（方案 §4.5 / F-2，受 U-4 约束）。")


if __name__ == "__main__":
    if "--remote" in sys.argv:
        remote_main(sys.argv[1:])
    else:
        local_main(sys.argv[1:])
