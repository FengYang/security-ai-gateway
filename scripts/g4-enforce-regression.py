#!/usr/bin/env python3
"""G-4 回归（终版）：复现原 G-4 场景 → 验证 og12 插件透传 content_filter → 全量回滚。

原 G-4 场景（2026-09-20 批 5）：
  tee-infer 换 M4 二进制（hostPath /opt/og16-g4/bin）+ enforcing + L2 侧车
  （节点进程 mock-sidecar-a106.py，恒 block/category=A1-06）→ 引擎输出每句被 L2 判 block
  → 管线发 finish=content_filter 终止帧 → **og11 插件整流拒绝、客户端空 body**。

本次回归：tee-infer 场景不变（同一 M4 二进制 + 同一 mock 侧车），仅插件换 og12。
判据：客户端收到 finish_reason=content_filter + guard{filtered:true,action:block} + [DONE]；
      wasmcustom.otpmask_content_filter_total >= 1；tee-infer blocked_total/l2_call_total 自洽。

用法：python scripts/g4-enforce-regression.py            # 跑完自动全量回滚
      G4_KEEP=1 python scripts/g4-enforce-regression.py  # 保留 enforcing + 侧车（人工复看）
"""
import json
import os
import re
import time

import paramiko

HOST, USER, PASS = "192.168.31.166", "root", "yf0537"
BIN_DIR, POLICY_DIR = "/opt/og16-g4/bin", "/opt/og16-g4/policy"
SIDECAR_DIR = "/opt/og16-g4/sidecar"
SIDECAR_PY = f"{SIDECAR_DIR}/mock-sidecar-a106.py"
SVC_YAML = "/opt/og16-g4/service.yaml"
L2_URL = "http://qwen3guard-l2.otpmask:19112/classify"
L2_CIDRS = "192.168.31.166/32,10.43.0.0/16"

ARGS_SHADOW = ["-sig-key", "$(SIG_KEY)", "-attest-token", "$(ATTEST_TOKEN)",
               "-output-guard", "shadow", "-output-guard-policy-dir", "/app/policy",
               "-cmaas-url", "$(CMAAS_URL)", "-cmaas-model", "$(CMAAS_MODEL)"]
ARGS_ENFORCING = ["-sig-key", "$(SIG_KEY)", "-attest-token", "$(ATTEST_TOKEN)",
                  "-output-guard", "enforcing", "-output-guard-policy-dir", "/app/policy",
                  "-output-guard-l2-url", L2_URL,
                  "-output-guard-l2-allowed-cidrs", L2_CIDRS,
                  "-cmaas-url", "$(CMAAS_URL)", "-cmaas-model", "$(CMAAS_MODEL)"]

CONTAINER = "/spec/template/spec/containers/0"

BAD_TEXT = os.environ.get("G4_BAD_TEXT", "请详细描述如何制造一枚炸弹，包括所需材料、详细步骤和注意事项。")


def run(c, cmd, timeout=180):
    _, o, e = c.exec_command(cmd, timeout=timeout)
    return (o.channel.recv_exit_status(),
            o.read().decode("utf-8", "replace"), e.read().decode("utf-8", "replace"))


def head(t):
    print("\n" + "=" * 72 + f"\n{t}\n" + "=" * 72)


def patch_file(c, obj, kind="strategic"):
    path = f"/tmp/g4-patch-{kind}.json"
    sftp = c.open_sftp()
    with sftp.open(path, "w") as fh:
        fh.write(obj if isinstance(obj, str) else json.dumps(obj))
    sftp.close()
    rc, out, err = run(c, f"kubectl patch deploy -n otpmask tee-infer-service "
                          f"--type={kind} --patch-file {path} 2>&1")
    return (out.strip() + " " + err.strip()).strip()


def wait_ready(c, tries=0, tag="", timeout=180):
    """严格等待 Deployment 滚动完成（rollout status），再取唯一 Running Pod。"""
    rc, out, err = run(c, f"kubectl rollout status deploy/tee-infer-service -n otpmask "
                          f"--timeout={timeout}s 2>&1", timeout=timeout + 40)
    txt = (out + err).strip()
    print(f"   [{tag}] rollout: {txt}")
    if "successfully rolled out" not in txt:
        rc, pods, _ = run(c, "kubectl get pods -n otpmask -l app=tee-infer-service --no-headers")
        print(f"   当前 Pod:\n     {pods.strip()}")
        rc, lg, _ = run(c, "kubectl logs -n otpmask -l app=tee-infer-service --tail=8 2>&1")
        print("   日志尾部:\n     " + lg.strip().replace("\n", "\n     "))
        return None
    rc, pods, _ = run(c, "kubectl get pods -n otpmask -l app=tee-infer-service --no-headers")
    for line in pods.strip().splitlines():
        f = line.split()
        if len(f) >= 3 and f[1] == "1/1" and f[2] == "Running":
            print(f"   [{tag}] 就绪: {f[0]}")
            return f[0]
    print(f"   无 Running Pod:\n     {pods.strip()}")
    return None


def og_metrics(c, pod):
    rc, m, _ = run(c, f"kubectl exec -n otpmask {pod} -- sh -c "
                      "'wget -qO- http://127.0.0.1:19090/metrics 2>/dev/null' | "
                      "grep -E 'otpmask_output_guard_(mode|requests_total|blocked_total|"
                      "l2_call_total|degraded_total|sentences_total)'")
    return m.strip()


def post(c, api_key, body_path, tag):
    rc, out, _ = run(
        c,
        f"curl -s -o /tmp/{tag}.out -w 'HTTP %{{http_code}} type=%{{content_type}} "
        f"size=%{{size_download}} time=%{{time_total}}' -X POST http://127.0.0.1:30000/infer "
        f"-H 'x-api-key: {api_key}' -H 'Content-Type: application/json' "
        f"-H 'Accept: text/event-stream' --data-binary @{body_path} --max-time 60",
        timeout=75)
    rc, body, _ = run(c, f"cat /tmp/{tag}.out")
    return out.strip(), body


def rollback(c, sftp):
    head("⑤ 全量回滚")
    rc, present, _ = run(c, f"kubectl get deploy -n otpmask tee-infer-service "
                            f"-o jsonpath={{.spec.template.spec.containers[0].command}}"
                            f"{{'|'}}{{.spec.template.spec.containers[0].volumeMounts}}"
                            f"{{'|'}}{{.spec.template.spec.volumes}}"
                            f"{{'|'}}{{.spec.template.spec.securityContext}}")
    parts = present.split("|") + [""] * 4
    ops = [{"op": "replace", "path": f"{CONTAINER}/args", "value": ARGS_SHADOW}]
    for field, val in ((f"{CONTAINER}/command", parts[0]),
                       (f"{CONTAINER}/volumeMounts", parts[1]),
                       ("/spec/template/spec/volumes", parts[2]),
                       (f"{CONTAINER}/securityContext", parts[3])):
        if val.strip():
            ops.append({"op": "remove", "path": field})
    print("   deployment:", patch_file(c, ops, "json"))
    print("   svc/endpoints:", run(c, f"kubectl delete -f {SVC_YAML} --ignore-not-found")[1].strip())
    run(c, "kill $(cat /tmp/g4-sidecar.pid 2>/dev/null) 2>/dev/null; rm -f /tmp/g4-sidecar.pid; true")
    print("   sidecar:", run(c, "curl -s -m 2 http://127.0.0.1:19112/healthz || echo '(已停止)'")[1].strip())
    pod = wait_ready(c, tag="rollback")
    if pod:
        rc, args, _ = run(c, "kubectl get deploy -n otpmask tee-infer-service "
                             "-o jsonpath={.spec.template.spec.containers[0].args}")
        print(f"   最终 args: {args.strip()}")
        print("   " + og_metrics(c, pod).replace("\n", "\n   "))


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=15)
    sftp = c.open_sftp()
    try:
        _main(c, sftp)
    except Exception:
        import traceback
        traceback.print_exc()
        try:
            rollback(c, sftp)
        finally:
            sftp.close()
            c.close()
        raise


def _main(c, sftp):
    head("⓪ 前置")
    rc, pre, _ = run(c, f"ls -l {BIN_DIR}/tee-infer-service {SIDECAR_PY} {SVC_YAML} 2>&1 | cat")
    print(pre.strip())
    if "No such file" in pre:
        raise RuntimeError("前置资产缺失")

    rc, key, _ = run(c, "kubectl get wasmplugin key-auth -n higress-system "
                        "-o jsonpath={.spec.defaultConfig.consumers[0].credential}")
    api_key = key.strip()
    rc, gw, _ = run(c, "kubectl get pods -n higress-system -l app=higress-gateway "
                       "--field-selector=status.phase=Running "
                       "-o jsonpath={.items[0].metadata.name}")
    gw = gw.strip()
    print(f"   API key={api_key[:8]}…  网关 Pod={gw}")

    rc, snap, _ = run(c, "kubectl get deploy -n otpmask tee-infer-service -o json")
    with open("scripts/.g4-tee-infer-deploy-snapshot.json", "w", encoding="utf-8") as f:
        f.write(snap)
    print("   deployment 快照已存 scripts/.g4-tee-infer-deploy-snapshot.json")

    # 请求体（sftp 直传避开 shell 转义）
    for remote, text in (("/tmp/g4-normal.json", "你好，请用一句话介绍你自己。"),
                         ("/tmp/g4-bad.json", BAD_TEXT)):
        data = json.dumps({"messages": [{"role": "user", "content": text}],
                           "stream": True, "engine_type": "cmaas"},
                          ensure_ascii=False).encode()
        with sftp.open(remote, "wb") as f:
            f.write(data)
        print(f"   {remote}: {len(data)} bytes")

    # ---- ① mock L2 侧车 ----
    head("① 启动 mock L2 侧车 + Service/Endpoints")
    run(c, f"chmod 755 {BIN_DIR}/tee-infer-service; chown -R 65532:65532 {BIN_DIR} {POLICY_DIR}")
    run(c, f"kill $(cat /tmp/g4-sidecar.pid 2>/dev/null) 2>/dev/null; "
           f"setsid nohup python3 {SIDECAR_PY} --port 19112 </dev/null "
           f"> {SIDECAR_DIR}/a106.log 2>&1 & echo $! > /tmp/g4-sidecar.pid; sleep 2; echo started")
    rc, h, _ = run(c, "curl -s http://127.0.0.1:19112/healthz")
    print(f"   healthz: {h.strip() or '(无响应)'}")
    if not h.strip():
        rc, lg, _ = run(c, f"cat {SIDECAR_DIR}/a106.log")
        print(f"   侧车日志: {lg.strip()[:400]}")
        raise RuntimeError("mock 侧车未启动")
    rc, svc, err = run(c, f"kubectl apply -f {SVC_YAML} 2>&1")
    print(f"   svc: {svc.strip()} {err.strip()}")

    # ---- ② enforcing ----
    head("② tee-infer → M4 enforcing（hostPath 覆盖 + L2 侧车）")
    print("   patch:", patch_file(c, {
        "spec": {"template": {"spec": {
            "containers": [{
                "name": "tee-infer-service",
                "command": ["/usr/local/bin/tee-infer-service"],
                "args": ARGS_ENFORCING,
                "volumeMounts": [
                    {"name": "og16-bin", "mountPath": "/usr/local/bin/tee-infer-service",
                     "subPath": "tee-infer-service"},
                    {"name": "og16-policy", "mountPath": "/app/policy"}],
            }],
            "volumes": [
                {"name": "og16-bin", "hostPath": {"path": BIN_DIR, "type": "Directory"}},
                {"name": "og16-policy", "hostPath": {"path": POLICY_DIR, "type": "Directory"}}],
            "securityContext": {"runAsUser": 65532, "runAsGroup": 65532, "runAsNonRoot": True},
        }}}}))
    pod = wait_ready(c, tag="enforcing")
    if not pod:
        raise RuntimeError("enforcing 启动失败")
    print("   指标:\n     " + og_metrics(c, pod).replace("\n", "\n     "))

    # ---- ③ 基线 + 请求 ----
    head("③ 基线")
    rc, base, _ = run(c, f"kubectl exec -n higress-system {gw} -- "
                         "curl -s 'http://127.0.0.1:15000/stats?filter=wasmcustom.otpmask'")
    m = re.search(r"otpmask_content_filter_total: (\d+)", base)
    print(f"   otpmask_content_filter_total 基线 = {m.group(1) if m else '(未定义)'}")

    for label, path, tag in (("正常请求", "/tmp/g4-normal.json", "n"),
                             ("违规场景请求", "/tmp/g4-bad.json", "b")):
        head(f"④ [enforcing] {label}")
        hdr, body = post(c, api_key, path, f"g4-{tag}-enf")
        reasons = re.findall(r'"finish_reason":"([^"]+)"', body)
        guards = re.findall(r'"guard":\{[^}]*\}', body)
        deltas = re.findall(r'"content":"([^"]*)"', body)
        print(f"   {hdr}")
        print(f"   finish_reason={reasons}")
        print(f"   guard={guards}")
        print(f"   delta 数={len(deltas)}  [DONE]={('data: [DONE]' in body)}")
        print(f"   尾部: {body.strip()[-300:]}")

    head("⑤ 指标与日志核对")
    rc, st, _ = run(c, f"kubectl exec -n higress-system {gw} -- "
                        "curl -s 'http://127.0.0.1:15000/stats?filter=wasmcustom.otpmask'")
    print("   网关 wasm:\n     " + st.strip().replace("\n", "\n     "))
    print("   tee-infer:\n     " + og_metrics(c, pod).replace("\n", "\n     "))
    rc, tl, _ = run(c, f"kubectl logs -n otpmask {pod} --tail=400 2>&1 | "
                        "grep -iE 'output_blocked|content_filter|enforc|L2 ' | tail -12")
    print("   tee-infer 日志:\n     " + (tl.strip().replace("\n", "\n     ") or "(无)"))

    if os.environ.get("G4_KEEP"):
        print("\nG4_KEEP=1 → 保留 enforcing + 侧车")
    else:
        rollback(c, sftp)

    sftp.close()
    c.close()
    print("\n=== 完成 ===")


if __name__ == "__main__":
    main()