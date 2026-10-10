#!/usr/bin/env python3
"""
otel-allowlist.py —— 变更 OTel Collector tail_sampling 的租户 allow-list。

自携带脚本（本地 WSL 运行）：
  python3 otel-allowlist.py --tenant t-smoke-001
  python3 otel-allowlist.py --tenant t-smoke-001 --sampling 100   # 同时调默认采样率

行为：
  1) 读取 otel-collector-config ConfigMap；
  2) 把 3 条 tail_sampling 策略中 key: tenant.id 后面的 values:[...]
     统一替换为目标租户（保留缩进，兼容已设置过的情况）；
  3) 可选：仅修改 tenant-default 策略的 probabilistic sampling_percentage；
  4) replace ConfigMap，rollout restart 并等待 collector 就绪。

前置：export SSH_PASSWORD。
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import k3s_remote  # noqa: E402

NAMESPACE = "otpmask"


def _run(cmd, timeout=180):
    p = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=timeout
    )
    return p.stdout, p.stderr, p.returncode


def local_main(argv):
    k3s_remote.run_script(os.path.abspath(__file__), *argv, timeout=300)


def _opt(argv, name, default=None):
    if name in argv:
        i = argv.index(name)
        if i + 1 < len(argv):
            return argv[i + 1]
    return default


def replace_allowlist(current, tenant):
    lines = current.split("\n")
    new_lines = []
    replacements = 0
    i = 0
    values_re = re.compile(r"^(\s*)values:\s*\[.*\]\s*$")
    while i < len(lines):
        line = lines[i]
        new_lines.append(line)
        if line.strip() == "key: tenant.id" and i + 1 < len(lines):
            m = values_re.match(lines[i + 1])
            if m:
                new_lines.append(f'{m.group(1)}values: ["{tenant}"]')
                replacements += 1
                i += 2
                continue
        i += 1
    return "\n".join(new_lines), replacements


def set_default_sampling(current, sampling):
    """只修改 tenant-default 策略块内的 sampling_percentage。"""
    start = current.find("- name: tenant-default")
    if start < 0:
        return current, False
    next_pol = current.find("\n      - name:", start + 1)
    end = next_pol if next_pol >= 0 else len(current)
    block = current[start:end]
    new_block, n = re.subn(
        r"sampling_percentage:\s*\d+",
        f"sampling_percentage: {sampling}",
        block,
    )
    if n == 0:
        return current, False
    return current[:start] + new_block + current[end:], True


def remote_main(argv):
    tenant = _opt(argv, "--tenant", "t-smoke-001")
    sampling = _opt(argv, "--sampling")

    print("=== 获取当前 collector 配置 ===")
    out, err, rc = _run(
        "kubectl get configmap otel-collector-config -n otpmask "
        "-o jsonpath='{.data.otel-collector\\.yaml}'"
    )
    if rc != 0:
        raise SystemExit(f"获取配置失败: {err.strip()[:200]}")

    cfg, replacements = replace_allowlist(out, tenant)
    print(f"allow-list 替换: {replacements} 处 -> {tenant}")
    if replacements != 3:
        raise SystemExit(
            f"预期替换 3 处，实际 {replacements} 处；配置结构可能已变化，终止"
        )

    if sampling is not None:
        cfg, ok = set_default_sampling(cfg, sampling)
        print(f"tenant-default sampling_percentage: "
              f"已设为 {sampling}" if ok else "未找到 sampling_percentage，跳过")

    with open("/tmp/otel-collector-patched.yaml", "w") as f:
        f.write(cfg)

    out, err, rc = _run(
        "kubectl create configmap otel-collector-config -n otpmask "
        "--from-file=otel-collector.yaml=/tmp/otel-collector-patched.yaml "
        "--dry-run=client -o yaml > /tmp/otel-new-cm.yaml && "
        "kubectl replace -f /tmp/otel-new-cm.yaml"
    )
    if rc != 0:
        raise SystemExit(f"ConfigMap 更新失败: {err.strip()[:300]}")
    print("ConfigMap 已更新")

    print("\n=== 重启 collector ===")
    _run("kubectl rollout restart deployment/otel-collector -n otpmask")
    out, err, rc = _run(
        "kubectl rollout status deployment/otel-collector -n otpmask --timeout=180s"
    )
    sys.stdout.write(out)
    if rc != 0:
        raise SystemExit("collector 重启后超时未就绪")
    print("完成")


if __name__ == "__main__":
    if "--remote" in sys.argv:
        remote_main(sys.argv[1:])
    else:
        local_main(sys.argv[1:])
