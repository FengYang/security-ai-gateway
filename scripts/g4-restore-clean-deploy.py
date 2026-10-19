#!/usr/bin/env python3
"""G-4 收尾：移除 tee-infer Deployment 上的 hostPath 二进制覆盖，还原 otpmask/tee-infer-service:og11 纯镜像部署。

背景：早前 G-4 轮次为跑节点 M4 二进制加了 hostPath 覆盖（og16-bin/og16-policy volume + volumeMount
+ command + pod 级 securityContext），那次回滚只回了 args，覆盖残留至今（本轮 G-4 回归前快照已存在）。

权威形态 = deploy/k8s/tee-infer-service.yaml：无 volumes / 无 command / 无 pod 级 securityContext
（非 root 由镜像 Dockerfile `USER 65532:65532` 保证；策略 /app/policy 由镜像烤入）。

流程：备份 → 依次探测 4 项覆盖字段 → JSON patch remove → rollout → 校验（无覆盖字段 / 模式 / 策略版本 /
进程 uid / 启动日志）→ 端到端冒烟；任一校验失败自动反向 patch 回滚。
"""
import os
import json
import sys

import paramiko

HOST, USER = "192.168.31.166", "root"
PASS = os.environ.get("SSH_PASSWORD")
if not PASS:
    raise SystemExit("[FATAL] 环境变量 SSH_PASSWORD 未设置（口令仅经环境变量注入，严禁硬编码/入库）")
NS = "otpmask"
DEPLOY = "tee-infer-service"
BACKUP = "/opt/og16-g4/tee-infer-deploy-preg4-cleanup.json"
PATCH_REMOVE = "/tmp/tee-infer-clean-remove.json"
PATCH_RESTORE = "/tmp/tee-infer-clean-restore.json"

# (JSON patch path, 备份用键路径)
TARGETS = [
    ("/spec/template/spec/volumes", ("spec", "template", "spec", "volumes")),
    ("/spec/template/spec/securityContext", ("spec", "template", "spec", "securityContext")),
    ("/spec/template/spec/containers/0/volumeMounts",
     ("spec", "template", "spec", "containers", 0, "volumeMounts")),
    ("/spec/template/spec/containers/0/command",
     ("spec", "template", "spec", "containers", 0, "command")),
]


def run(c, cmd, timeout=90):
    _, out, err = c.exec_command(cmd, timeout=timeout)
    o = out.read().decode("utf-8", "replace")
    e = err.read().decode("utf-8", "replace")
    rc = out.channel.recv_exit_status()
    return rc, o, e


def head(t):
    print("\n" + "=" * 68)
    print(t)
    print("=" * 68)


def write_remote(sftp, path, text):
    with sftp.open(path, "w") as f:
        f.write(text)


def dig(obj, keys):
    cur = obj
    for k in keys:
        if isinstance(cur, list):
            if k >= len(cur):
                return None
            cur = cur[k]
        else:
            cur = cur.get(k)
        if cur is None:
            return None
    return cur


def deploy_json(c):
    rc, out, err = run(c, f"kubectl get deploy -n {NS} {DEPLOY} -o json", timeout=60)
    if rc != 0:
        raise RuntimeError(f"读取 deployment 失败: {err.strip()}")
    return json.loads(out)


def apply_patch(c, sftp, ops, tag, path):
    if not ops:
        print(f"   [{tag}] 无可执行 op，跳过")
        return True
    write_remote(sftp, path, json.dumps(ops, ensure_ascii=False))
    rc, out, err = run(c, f"kubectl patch deploy -n {NS} {DEPLOY} "
                          f"--type=json --patch-file {path} 2>&1")
    print(f"   [{tag}] {out.strip() or err.strip()}")
    return rc == 0 and "patched" in out


def wait_rollout(c, timeout=180):
    rc, out, err = run(c, f"kubectl rollout status deploy/{DEPLOY} -n {NS} "
                          f"--timeout={timeout}s 2>&1", timeout=timeout + 40)
    txt = (out + err).strip()
    print(f"   rollout: {txt}")
    if "successfully rolled out" not in txt:
        return None
    rc, pods, _ = run(c, f"kubectl get pods -n {NS} -l app={DEPLOY} --no-headers")
    for line in pods.strip().splitlines():
        f = line.split()
        if len(f) >= 3 and f[1] == "1/1" and f[2] == "Running":
            return f[0]
    return None


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=15)
    sftp = c.open_sftp()

    head("[1] 备份当前 deployment（回滚用）")
    d = deploy_json(c)
    write_remote(sftp, BACKUP, json.dumps(d, ensure_ascii=False))
    orig_args = dig(d, ("spec", "template", "spec", "containers", 0, "args"))
    print(f"   备份写入 {BACKUP}")
    print(f"   当前 args: {orig_args}")

    remove_ops, restore_ops, saved = [], [], {}
    for json_path, key_path in TARGETS:
        val = dig(d, key_path)
        if val is not None:
            remove_ops.append({"op": "remove", "path": json_path})
            restore_ops.append({"op": "add", "path": json_path, "value": val})
            saved[json_path] = val
    print(f"   待移除字段 {len(remove_ops)} 项：{list(saved)}")
    for k, v in saved.items():
        print(f"     - {k} = {json.dumps(v, ensure_ascii=False)[:160]}")

    if not remove_ops:
        print("\n   deployment 已是纯镜像形态，无需改动。=== 完成 ===")
        sftp.close()
        c.close()
        return

    head("[2] 移除 hostPath 覆盖（JSON patch）")
    if not apply_patch(c, sftp, remove_ops, "remove", PATCH_REMOVE):
        print("   patch 失败，未做任何改动。=== 中止 ===")
        sys.exit(1)

    head("[3] 等待滚动完成")
    pod = wait_rollout(c)
    if not pod:
        print("   rollout 失败 → 回滚")
        apply_patch(c, sftp, restore_ops, "restore", PATCH_RESTORE)
        wait_rollout(c)
        sys.exit(1)
    print(f"   Pod: {pod}")

    head("[4] 字段校验（应全部为空 / args 仍 shadow）")
    ok = True
    for json_path, _ in TARGETS:
        rc, out, _ = run(c, f"kubectl get deploy -n {NS} {DEPLOY} "
                            f"-o jsonpath='{{{json_path[1:]}}}'")
        v = out.strip()
        status = "OK" if v in ("", "null") else "!! 仍存在"
        if v not in ("", "null"):
            ok = False
        print(f"   {json_path}: {status} {v[:120]}")
    rc, args, _ = run(c, f"kubectl get deploy -n {NS} {DEPLOY} "
                         f"-o jsonpath='{{.spec.template.spec.containers[0].args}}'")
    print(f"   args: {args.strip()}")
    if "shadow" not in args:
        ok = False
        print("   !! args 未处于 shadow")

    head("[5] 运行时校验（模式 / 策略版本 / 进程 uid）")
    rc, m, _ = run(c, f"kubectl exec -n {NS} {pod} -- wget -qO- "
                      "http://127.0.0.1:19090/metrics 2>/dev/null")
    for want in ('output_guard_mode{mode="shadow"} 1',
                 'output_guard_policy_version{version="pv2026.09.16"} 1'):
        hit = want in m
        ok = ok and hit
        print(f"   {want}: {'OK' if hit else '!! 缺失'}")
    rc, uid, err = run(c, f"kubectl exec -n {NS} {pod} -- id 2>&1")
    print(f"   id: {uid.strip() or err.strip()}")
    if "65532" not in uid:
        print("   !! 进程非 65532（镜像 USER 未生效）")
    rc, log, _ = run(c, f"kubectl logs -n {NS} {pod} --tail=200 2>&1 | "
                        "grep -iE '输出侧内容审查|output-guard|error|fatal' | head -8")
    print("   log: " + (log.strip().replace("\n", "\n        ") or "(无匹配)"))

    head("[6] 端到端冒烟（网关 → tee-infer shadow 放行）")
    rc, gw, _ = run(c, "kubectl get pods -n higress-system --no-headers | grep higress-gateway | head -1")
    gw_pod = gw.split()[0] if gw.strip() else ""
    rc, key, _ = run(c, "kubectl get wasmplugin key-auth -n higress-system "
                        "-o jsonpath='{.spec.defaultConfig.consumers[0].credential}'")
    api_key = key.strip()
    print(f"   网关 Pod {gw_pod} / key {api_key[:8]}…")
    body = {"messages": [{"role": "user", "content": "你好，请用一句话介绍你自己。"}],
            "stream": True, "engine_type": "cmaas"}
    with sftp.open("/tmp/tee-clean-smoke.json", "w") as f:
        f.write(json.dumps(body, ensure_ascii=False))
    rc, hdr, _ = run(c,
                     f"curl -s -o /tmp/tee-clean-smoke.out "
                     f"-w 'HTTP %{{http_code}} type=%{{content_type}} size=%{{size_download}}' "
                     f"-X POST http://127.0.0.1:30000/infer -H 'x-api-key: {api_key}' "
                     f"-H 'Content-Type: application/json' -H 'Accept: text/event-stream' "
                     f"--data-binary @/tmp/tee-clean-smoke.json --max-time 30", timeout=45)
    print(f"   {hdr.strip()}")
    rc, sz, _ = run(c, "wc -c < /tmp/tee-clean-smoke.out")
    smoke_ok = "HTTP 200" in hdr and int(sz.strip() or 0) > 0
    if not smoke_ok:
        ok = False
    print(f"   body bytes: {sz.strip()} → {'OK' if smoke_ok else '!! 冒烟失败'}")

    if ok:
        print("\n=== 完成：已还原纯镜像部署，全部校验通过 ===")
        print(f"    （回滚备份：{BACKUP}；反向 patch：{PATCH_RESTORE}）")
    else:
        print("\n!! 存在校验失败项 → 回滚")
        apply_patch(c, sftp, restore_ops, "restore", PATCH_RESTORE)
        wait_rollout(c)
        sys.exit(1)

    sftp.close()
    c.close()


if __name__ == "__main__":
    main()