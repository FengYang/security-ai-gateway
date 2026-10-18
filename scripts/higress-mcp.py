#!/usr/bin/env python3
"""
higress-mcp.py —— 启用 / 回滚 Higress 原生 MCP Server（`higress-config` 的 `mcpServer` 段）。

自携带脚本（本地 WSL/Linux 运行；沿用 k3s_remote 上传执行）：
  python3 scripts/higress-mcp.py --profile native
  python3 scripts/higress-mcp.py --profile native --dry-run
  python3 scripts/higress-mcp.py --rollback

行为（--profile native，对应"情况① 客户自建可信内网"）：
  1) 前置校验：Redis 服务与端点可达（若指向集群内 Redis）+ cryptop 就绪（RK-9，轻量
     只读：sidecar 容器 + Secret；缺省时 native 显式警告继续、secure 预检失败，P2-1 §7.2.3）；
  2) **合并**（非覆盖）写入 `data.higress.mcpServer`（保留 tracing 等既有键）；
  3) 滚动重启 gateway 并等待 Ready；
  4) 冒烟：断言 `mcpServer.enable=true` 已加载 + 探测 MCP 入口（信息性）。

`--profile secure`（情况② 客户不信任基础设施）：在 native 流程**之上**追加 4 步
（**不改 native 行为**，沿用 --dry-run/--rollback 语义）：
  5) 敏感轨链路校验：Ingress `mcp-secure-tools` 生效 + WasmPlugin `otpmask` 覆盖该路由名；
  6) 策略下发：`POST <tee>/config/mcp/policy`（body 取自 --mcp-policy-file，含已签名 {catalog,policy}）；
  7) 就绪校验：`GET <tee>/config/mcp` 且断言 ready=true；
  8) 冒烟：向 `/mcp-servers/secure-tools` 投递非段① 信封的不透明字节 → 断言 fail-closed。
  dry-run：以上 4 步**仅列出、不做任何集群读写**（保证"列出 4 步且零变更"）。

参数：
  --profile native|secure  必填
  --tee-url                tee-infer 基址（缺省按 Running pod IP + 19090 自动发现）
  --tee-token              tee-infer 管理令牌（X-Admin-Token）；或用 env OTP_TEE_ADMIN_TOKEN
  --mcp-policy-file        secure 步骤② 请求体 JSON（{catalog?, policy?}，已签名对象）
  --dry-run                只打印将要写入的 mcpServer 段与差异，不做任何变更
  --rollback               删除 `mcpServer` 键并重启（等价"一键关闭"）
  --redis-address          默认 redis-ratelimit.otpmask.svc.cluster.local:6379（方案 §4.3 R1）
                           R2（官方 helm enableRedis）改为 redis-stack-server.higress-system.svc.cluster.local:6379
  --sse-suffix             MCP 客户端 SSE 后缀，默认 /sse
  --mcp-server-file        以片段文件（含 `mcpServer` 键）为源写入 mcpServer 段（T-2 ②
                            配置化：match_list/servers 按实测形态填写；缺省用内置空骨架）；
                            经本机入口运行时会自动随 bundle 上传（远程以 K3S_BUNDLE_DIR 定位）

前置：export SSH_PASSWORD（严禁硬编码）。
依据：《GA-Higress-MCP接入与打通-技术实现方案》v1.7 §4.1 / §4.3 / §6.3.2 / §7.2.3 / §8。
注意：`higress-config` 的 `higress` 字段还含 tracing 等**运行期追加**内容，故本脚本只
      **合并/删除 `mcpServer` 键**，绝不以整份 ConfigMap 覆盖（防丢 tracing）。
"""
import json
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

# ---- secure 分支（情况② 敏感轨）常量 ----
TEE_SVC_NS = "otpmask"
TEE_SVC_LABEL = "app=tee-infer-service"
TEE_SVC_PORT = "19090"
SECURE_INGRESS = "mcp-secure-tools"   # deploy/higress/ingress-mcp.yaml
SECURE_PATH = "/mcp-servers/secure-tools"
OTPMASK_PLUGIN = "otpmask"            # deploy/higress/otpmask-plugin.yaml（matchRules 含 SECURE_INGRESS）

# ---- T-1 前置校验（cryptop 就绪，RK-9）常量 ----
GW_DEPLOY = "higress-gateway"         # 网关 Deployment（sidecar 注入对象）
CRYPTO_SIDECAR = "cryptopsvc"         # sidecar 容器名（cryptopsvc-sidecar-patch.yaml）
CRYPTO_SECRET = "cryptop-static-keys" # 静态密钥 Secret（同 patch 文件创造）


def _run(cmd, timeout=300):
    import subprocess

    p = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=timeout
    )
    return p.stdout, p.stderr, p.returncode


def local_main(argv):
    """本机入口：上传本脚本（+ `--mcp-server-file` 片段所在目录）到节点，以 --remote 执行。"""
    bundle_dir = None
    frag = _opt(argv, "--mcp-server-file")
    if frag:
        frag_abs = os.path.abspath(frag)
        if not os.path.isfile(frag_abs):
            raise SystemExit(f"--mcp-server-file 不存在: {frag_abs}")
        bundle_dir = os.path.dirname(frag_abs)
        argv = list(argv)
        argv[argv.index("--mcp-server-file") + 1] = os.path.basename(frag_abs)
    k3s_remote.run_script(
        os.path.abspath(__file__), *argv, timeout=900, bundle_dir=bundle_dir
    )


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


def check_cryptop(profile, dry_run):
    """T-1 前置校验：cryptop 就绪（RK-9，段① 密态链路必需；轻量只读）。

    语义（P2-1 §7.2.3）：加密依赖不可用**不得静默**——native（明文轨）显式警告后继续；
    secure（敏感轨）预检失败即拒绝（fail-closed）。
    深度验证（Pod 内 19097 探活 / config_dump 簇物化）属 T-1 ① 部署闭环留证，见
    《GA-Higress-MCP接入与打通》§6.3.2「P0 前置检查清单」。
    """
    print("\n-- cryptop 前置校验（RK-9；检查清单见 §6.3.2）")
    if dry_run:
        print("   [dry-run] 将执行以下只读校验（零变更）：")
        print(f"     ① 网关 Deployment（{GW_DEPLOY}）含 sidecar 容器 {CRYPTO_SIDECAR}")
        print(f"     ② Secret {CRYPTO_SECRET} 存在")
        return
    ok = True
    names, _, rc = _run(
        f"kubectl get deployment {GW_DEPLOY} -n {CM_NS} "
        "-o jsonpath='{.spec.template.spec.containers[*].name}'"
    )
    has_sidecar = rc == 0 and CRYPTO_SIDECAR in names.split()
    print(f"   ① sidecar 容器（{CRYPTO_SIDECAR}）: {'存在' if has_sidecar else '缺失'}")
    ok = ok and has_sidecar
    _, _, rc = _run(f"kubectl get secret {CRYPTO_SECRET} -n {CM_NS}")
    has_secret = rc == 0
    print(f"   ② Secret（{CRYPTO_SECRET}）: {'存在' if has_secret else '缺失'}")
    ok = ok and has_secret
    if ok:
        print("   cryptop 前置满足")
        return
    fix = (
        "按 deploy/higress/cryptopsvc-sidecar-patch.yaml 注入（P2-1 T-1；"
        "清单见《GA-Higress-MCP接入与打通》§6.3.2）"
    )
    if profile == "secure":
        raise SystemExit(
            f"[secure] cryptop 前置未满足（RK-9）：{fix}；敏感轨 fail-closed，拒绝继续。"
        )
    print(
        f"   [警告] cryptop 前置未满足（RK-9）：{fix}；"
        "native（明文轨）继续启用，段① 密态链路当前不可用。"
    )


def _load_mcp_server_section(path):
    """读取片段文件中的 `mcpServer` 映射（T-2 ② 配置化；R-8 仅合并该键）。"""
    import yaml

    try:
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
    except OSError as e:
        raise SystemExit(f"--mcp-server-file 不可读: {path}（{e}）")
    sec = doc.get("mcpServer") if isinstance(doc, dict) else None
    if not isinstance(sec, dict):
        raise SystemExit(f"--mcp-server-file 缺少 mcpServer 映射: {path}")
    for key in ("match_list", "servers"):
        if key in sec and not isinstance(sec[key], list):
            raise SystemExit(f"--mcp-server-file 的 {key} 必须为列表: {path}")
    return sec


def write_mcp_server(redis_addr, sse_suffix, dry_run, mcp_server_file=None):
    cm, hig = _read_higress()
    existed = "mcpServer" in hig
    if mcp_server_file:
        print(f"-- 片段文件: {mcp_server_file}")
        sec = _load_mcp_server_section(mcp_server_file)
    else:
        sec = {}
    # 安全兜底：enable 强制开；sse 后缀/redis/两列表缺省补齐（片段值优先）
    sec["enable"] = True
    sec.setdefault("sse_path_suffix", sse_suffix)
    redis = sec.setdefault("redis", {})
    if not redis.get("address"):
        redis.setdefault("username", "")
        redis.setdefault("password", "")
        redis.setdefault("db", 0)
        redis["address"] = redis_addr
    elif redis["address"] != redis_addr:
        print(f"   [注意] 片段自带 redis.address={redis['address']}（--redis-address 未生效）")
    sec.setdefault("match_list", [])
    sec.setdefault("servers", [])
    hig["mcpServer"] = sec
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
# secure 追加步骤（情况② 敏感轨；native 之上追加，不改 native 行为）
# --------------------------------------------------------------------------- #
def tee_base_url(override):
    """tee-infer 基址：--tee-url 覆盖；否则按 Running pod IP + 容器端口发现（与 native 冒烟同法，
    经节点可达 pod IP，避免 ClusterIP 在集群外不可达）。"""
    if override:
        return override.rstrip("/")
    out, err, rc = _run(
        f"kubectl get pods -n {TEE_SVC_NS} -l {TEE_SVC_LABEL} "
        "--field-selector=status.phase=Running -o jsonpath='{.items[0].status.podIP}'"
    )
    ip = out.strip()
    if rc != 0 or not ip:
        raise SystemExit(f"未发现运行中的 tee-infer pod（ns={TEE_SVC_NS}）：{err.strip()[:200]}")
    return f"http://{ip}:{TEE_SVC_PORT}"


def tee_http(base, path, method="GET", token="", body_file=None, timeout=15):
    """对 tee-infer 发一次请求，返回 (body, http_code)。"""
    hdr = f"-H 'X-Admin-Token: {token}'" if token else ""
    data = f"--data-binary @{body_file}" if body_file else ""
    cmd = (
        f"curl -s -w '\\n%{{http_code}}' --connect-timeout {timeout} -X {method} {hdr} "
        f"-H 'Content-Type: application/json' {data} {base}{path}"
    )
    out, err, rc = _run(cmd, timeout=timeout + 5)
    if rc != 0:
        return f"curl rc={rc}: {err.strip()[:120]}", ""
    parts = out.rsplit("\n", 1)
    if len(parts) != 2:
        return out.strip(), ""
    return parts[0].strip(), parts[1].strip()


def check_secure_route(dry_run):
    """① 敏感轨链路校验：Ingress 生效 + otpmask 插件覆盖该路由名。"""
    print("\n=== [secure] 1/4 敏感轨链路校验 ===")
    print(f"   断言：Ingress {SECURE_INGRESS}（ns {CM_NS}）path={SECURE_PATH}")
    print(f"         WasmPlugin {OTPMASK_PLUGIN}（ns {CM_NS}）matchRules 含路由名 {SECURE_INGRESS}")
    if dry_run:
        print("   [dry-run] 未执行（零变更）")
        return
    path, err, rc = _run(
        f"kubectl get ingress {SECURE_INGRESS} -n {CM_NS} "
        "-o jsonpath='{.spec.rules[0].http.paths[0].path}'"
    )
    if rc != 0 or path.strip() != SECURE_PATH:
        raise SystemExit(
            f"敏感轨 Ingress 未就绪（实得 path={path.strip()!r}，期望 {SECURE_PATH}）：{err.strip()[:200]}"
        )
    print(f"   Ingress OK：{path.strip()}")
    rules, err, rc = _run(f"kubectl get wasmplugin {OTPMASK_PLUGIN} -n {CM_NS} -o yaml")
    if rc != 0 or SECURE_INGRESS not in rules:
        raise SystemExit(
            f"otpmask 插件未覆盖敏感轨路由（matchRules 未见 {SECURE_INGRESS}）：{err.strip()[:200]}"
        )
    print(f"   插件覆盖 OK：{SECURE_INGRESS}")


def push_mcp_policy(base, token, policy_file, dry_run):
    """② 策略下发：POST /config/mcp/policy（body 须含已签名 catalog/policy）。"""
    print("\n=== [secure] 2/4 策略下发（POST /config/mcp/policy）===")
    print(f"   body 来源：--mcp-policy-file={policy_file or '(未提供)'}（须为 {{catalog?, policy?}} 已签名 JSON）")
    if dry_run:
        print("   [dry-run] 未执行（零变更）")
        return
    if not policy_file:
        raise SystemExit("缺少 --mcp-policy-file（含已签名 {catalog, policy} 的 JSON）")
    if not os.path.exists(policy_file):
        raise SystemExit(f"策略文件不存在：{policy_file}")
    body, code = tee_http(base, "/config/mcp/policy", "POST", token, policy_file)
    if code != "200":
        raise SystemExit(f"MCP 策略下发失败（HTTP {code}）：{body[:200]}")
    print(f"   下发响应：{body[:300]}")


def verify_mcp_ready(base, token, dry_run):
    """③ 就绪校验：GET /config/mcp 且断言 ready=true（fail-closed：未就绪不得宣告成功）。"""
    print("\n=== [secure] 3/4 就绪校验（GET /config/mcp）===")
    if dry_run:
        print("   断言：ready=true")
        print("   [dry-run] 未执行（零变更）")
        return
    body, code = tee_http(base, "/config/mcp", "GET", token)
    if code != "200":
        raise SystemExit(f"就绪快照读取失败（HTTP {code}）：{body[:200]}")
    try:
        snap = json.loads(body)
    except ValueError:
        raise SystemExit(f"就绪快照非 JSON：{body[:200]}")
    if not snap.get("ready"):
        raise SystemExit(f"MCP 策略未就绪（ready={snap.get('ready')}）：{snap}")
    print(f"   就绪 OK：{snap}")


def smoke_secure(dry_run):
    """④ 冒烟：向敏感轨投递**非段① 信封的不透明字节** → 断言 fail-closed（非 2xx）。

    说明：完整「段① 信封（opaque 载荷）搬运」需客户端侧会话握手（ECDH/K_enc），
    超出本部署脚本范围；此处以「不透明字节被拒」验证敏感轨已挂载且**不降级明文**。
    """
    print("\n=== [secure] 4/4 冒烟（opaque 载荷 / fail-closed）===")
    if dry_run:
        print(f"   将向 http://<gateway-pod-ip>:{GW_PORT}{SECURE_PATH} 投递非段① 信封的不透明字节，")
        print("   断言 HTTP 非 2xx（fail-closed；明文/裸字节不得被放行）。")
        print("   [dry-run] 未执行（零变更）")
        return
    pod, _, _ = _run(
        f"kubectl get pods -n {CM_NS} -l app=higress-gateway "
        "--field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}'"
    )
    pod = pod.strip()
    ip, _, _ = _run(f"kubectl get pod {pod} -n {CM_NS} -o jsonpath='{{.status.podIP}}'")
    ip = ip.strip()
    code, _, _ = _run(
        f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 3 -X POST "
        f"-H 'Content-Type: application/octet-stream' --data-binary 'otpmask-opaque-probe' "
        f"http://{ip}:{GW_PORT}{SECURE_PATH}",
        timeout=15,
    )
    code = code.strip()
    if code.startswith("2"):
        raise SystemExit(f"冒烟失败：不透明载荷未被拒绝（HTTP {code}）——敏感轨 fail-closed 未生效")
    print(f"   不透明载荷被拒（HTTP {code}）→ 敏感轨已挂载且 fail-closed ✓")


def run_secure_steps(dry_run, tee_url, tee_token, policy_file):
    """在 native 流程之上叠加 4 个敏感轨步骤（dry-run 仅列出，零变更）。"""
    print("\n== [secure] 敏感轨追加步骤（4 步）==")
    if dry_run:
        check_secure_route(True)
        push_mcp_policy(None, None, policy_file, True)
        verify_mcp_ready(None, None, True)
        smoke_secure(True)
        print("\n[dry-run] secure 追加步骤已列出（未做任何集群读写）")
        return
    base = tee_base_url(tee_url)
    print(f"-- tee-infer 基址: {base}")
    check_secure_route(False)
    push_mcp_policy(base, tee_token, policy_file, False)
    verify_mcp_ready(base, tee_token, False)
    smoke_secure(False)


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
def remote_main(argv):
    profile = _opt(argv, "--profile")
    dry_run = "--dry-run" in argv
    do_rollback = "--rollback" in argv
    redis_addr = _opt(argv, "--redis-address", DEFAULT_REDIS)
    sse_suffix = _opt(argv, "--sse-suffix", "/sse")
    tee_url = _opt(argv, "--tee-url")
    tee_token = _opt(argv, "--tee-token", os.environ.get("OTP_TEE_ADMIN_TOKEN", ""))
    mcp_policy_file = _opt(argv, "--mcp-policy-file")
    mcp_server_file = _opt(argv, "--mcp-server-file")
    if mcp_server_file and not os.path.isabs(mcp_server_file):
        bundle = os.environ.get("K3S_BUNDLE_DIR", "")
        if not bundle:
            raise SystemExit(
                "--mcp-server-file 为相对路径但未设置 K3S_BUNDLE_DIR"
                "（应经本机入口 local_main 上传后执行）"
            )
        mcp_server_file = os.path.join(bundle, mcp_server_file)

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
    if profile not in ("native", "secure"):
        raise SystemExit(f"未知 profile: {profile}（仅支持 native|secure）")

    print("=== Step 1: 前置校验（Redis + cryptop）===")
    check_redis(redis_addr)
    check_cryptop(profile, dry_run)

    print("\n=== Step 2: 合并写入 mcpServer 段 ===")
    changed = write_mcp_server(redis_addr, sse_suffix, dry_run, mcp_server_file)
    if not changed:
        if profile == "native":
            print("\n[dry-run] 结束（未变更）")
            return
        # secure dry-run：native 基础段未变更，但仍须**列出** 4 个追加步骤（验收：列出 4 步且零变更）
    else:
        print("\n=== Step 3: 重启 gateway ===")
        restart_gateway()

        print("\n=== Step 4: 冒烟 ===")
        smoke(sse_suffix)

    if profile == "secure":
        run_secure_steps(dry_run, tee_url, tee_token, mcp_policy_file)
        if changed:
            print("\n完成：MCP Server（secure / 情况②）已启用（native 基础 + 敏感轨 4 步）。")
        return

    print("\n完成：MCP Server（native / 情况①）已启用。"
          "注意：完整 MCP 握手需注册 MCP 服务（方案 §4.5 / F-2，受 U-4 约束）。")


if __name__ == "__main__":
    if "--remote" in sys.argv:
        remote_main(sys.argv[1:])
    else:
        local_main(sys.argv[1:])
