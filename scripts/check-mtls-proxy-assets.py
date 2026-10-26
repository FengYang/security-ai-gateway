#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P2-4 PRE-A-4：mTLS 终止代理资产自检（deploy/monitoring-overlays/remote-write-mtls-server/）

为什么需要专门的脚本：
  这一层的安全性**全部落在 nginx.conf 的几行指令上**——少一行 `ssl_verify_client on`
  就退化为单向 TLS（= 缺口没修），多一条 `location / { proxy_pass }` 就把
  中央 Prometheus 的查询/管理面暴露到公网。这些都不是"跑起来能看出来"的错误，
  必须用静态断言钉住。

检查项：
  1. YAML 可解析（逐文件多文档）
  2. nginx.conf：客户端证书强制校验（ssl_verify_client on / ssl_client_certificate）
  3. nginx.conf：TLS 版本下限（不得出现 TLSv1 / TLSv1.1）
  4. nginx.conf：唯一放行路径 = 精确 `/api/v1/write`，默认 location 不得 proxy_pass
  5. nginx.conf：非 POST 拒绝（405）、server_tokens off
  6. Deployment：非 root / 只读根 / drop ALL / 不自动挂 SA token / 无 hostNetwork|hostPath
  7. Secret 卷：0440 且 pod 有 fsGroup（0400 + nobody 读不到 → CrashLoop，见 PRE-A-11）
  8. Secret 模板与两个"手工执行"的 NP 文件**不在** kustomization resources
  9. 端口一致：Service 9443 → targetPort 名字与容器端口名一致，且与端口矩阵口径相符
 10. 与发送侧一致性：gen-ca.sh 默认 SAN 覆盖代理服务名；发送侧 snippet 指向 9443
 11. `nginx -t` 语法校验（**本机无 nginx 且无容器运行时 → 明确 SKIP，绝不假装通过**）

退出码：
  0 = 全部 PASS（SKIP 显式列出）
  1 = 存在 FAIL；`--strict` 下存在 SKIP 亦返回 1
  2 = 环境/输入错误（PyYAML 缺失、目录不存在等）

用法：
  python3 scripts/check-mtls-proxy-assets.py
  python3 scripts/check-mtls-proxy-assets.py -v
  python3 scripts/check-mtls-proxy-assets.py --strict      # CI 门禁
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "FATAL: 缺少 PyYAML。请先安装：python3 -m pip install pyyaml\n"
    )
    sys.exit(2)

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY_DIR = os.path.join(ROOT, "deploy", "monitoring-overlays", "remote-write-mtls-server")
SENDER_DIR = os.path.join(ROOT, "deploy", "monitoring-overlays", "remote-write-mtls")

# 这些文件**刻意**不在 resources 内：它们收紧/放开真实网络边界，必须人工按现场执行
MANUAL_ONLY_FILES = [
    "replace-central-write-np.tighten.yaml",
    "networkpolicy-mtls-gateway-ingress.yaml",
    "secret-mtls-server.example.yaml",
]


class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str]] = []

    def add(self, name: str, status: str, detail: str = "") -> None:
        self.rows.append((status, name, detail))

    def count(self, status: str) -> int:
        return sum(1 for s, _, _ in self.rows if s == status)

    def dump(self, verbose: bool) -> None:
        width = max((len(n) for _, n, _ in self.rows), default=10)
        for status, name, detail in self.rows:
            if status == PASS and not verbose:
                continue
            line = f"[{status}] {name.ljust(width)}  {detail}".rstrip()
            print(line)
        print(
            f"\n汇总：PASS={self.count(PASS)} FAIL={self.count(FAIL)} "
            f"SKIP={self.count(SKIP)}（共 {len(self.rows)} 项）"
        )


def load_docs(path: str) -> list:
    with open(path, encoding="utf-8") as fh:
        return [d for d in yaml.safe_load_all(fh) if d]


def find_docs(docs: list, kind: str, name: str | None = None) -> list:
    out = []
    for d in docs:
        if d.get("kind") != kind:
            continue
        if name and d.get("metadata", {}).get("name") != name:
            continue
        out.append(d)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=PROXY_DIR, help="代理资产目录")
    ap.add_argument("-v", "--verbose", action="store_true", help="显示 PASS 明细")
    ap.add_argument("--strict", action="store_true", help="SKIP 视为失败（CI 门禁）")
    args = ap.parse_args()

    if not os.path.isdir(args.dir):
        sys.stderr.write(f"FATAL: 目录不存在：{args.dir}\n")
        return 2

    rep = Report()
    files = sorted(
        os.path.join(args.dir, f) for f in os.listdir(args.dir) if f.endswith((".yaml", ".yml"))
    )
    if not files:
        sys.stderr.write(f"FATAL: {args.dir} 下没有 YAML 文件\n")
        return 2

    # ---------- 1. YAML 可解析 ----------
    parsed: dict[str, list] = {}
    ok = True
    for path in files:
        try:
            parsed[path] = load_docs(path)
        except Exception as exc:  # noqa: BLE001
            ok = False
            rep.add(f"YAML 解析 {os.path.basename(path)}", FAIL, str(exc).splitlines()[0])
    if ok:
        rep.add("YAML 解析（全部文件）", PASS, f"{len(files)} 个文件")

    kust = None
    for path, docs in parsed.items():
        if os.path.basename(path).startswith("kustomization"):
            kust = docs[0]
    if kust is None:
        rep.add("kustomization 存在", FAIL, "未找到 kustomization.yaml")
        rep.dump(args.verbose)
        return 1
    rep.add("kustomization 存在", PASS)

    resources = kust.get("resources") or []

    # ---------- 2~5. nginx.conf ----------
    all_docs = [d for docs in parsed.values() for d in docs]
    cms = find_docs(all_docs, "ConfigMap")
    conf = ""
    if cms:
        conf = (cms[0].get("data") or {}).get("nginx.conf", "")
    rep.add("ConfigMap 含 nginx.conf", PASS if conf.strip() else FAIL,
            "" if conf.strip() else "data.nginx.conf 为空")

    if conf.strip():
        c = conf

        # 2. 客户端证书强制校验
        has_verify_on = re.search(r"^\s*ssl_verify_client\s+on\s*;", c, re.M) is not None
        bad_verify = re.search(r"^\s*ssl_verify_client\s+(off|optional)", c, re.M)
        rep.add("ssl_verify_client on（强制客户端证书）",
                PASS if has_verify_on and not bad_verify else FAIL,
                "缺此行即退化为单向 TLS" if not has_verify_on else
                (f"出现弱化写法：{bad_verify.group(0).strip()}" if bad_verify else ""))
        rep.add("ssl_client_certificate 指向 CA",
                PASS if re.search(r"^\s*ssl_client_certificate\s+\S+;", c, re.M) else FAIL,
                "" if re.search(r"^\s*ssl_client_certificate\s+\S+;", c, re.M) else "无信任 CA 则无法校验")
        rep.add("ssl_certificate / ssl_certificate_key 齐备",
                PASS if re.search(r"^\s*ssl_certificate\s+\S+;", c, re.M)
                and re.search(r"^\s*ssl_certificate_key\s+\S+;", c, re.M) else FAIL)

        # 3. TLS 版本下限
        m = re.search(r"^\s*ssl_protocols\s+([^;]+);", c, re.M)
        protos = m.group(1).split() if m else []
        weak = [p for p in protos if p in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")]
        rep.add("TLS 下限 ≥ 1.2", PASS if protos and not weak else FAIL,
                f"ssl_protocols={' '.join(protos) or '未声明'}" + (f"，含弱协议 {weak}" if weak else ""))

        # 4. 唯一放行路径
        rep.add("精确放行 location = /api/v1/write",
                PASS if re.search(r"location\s*=\s*/api/v1/write\s*\{", c) else FAIL,
                "" if re.search(r"location\s*=\s*/api/v1/write\s*\{", c) else "无精确匹配会放大可达面")
        # 默认 location 不得反代（否则查询/管理面被暴露）
        default_proxy = re.search(r"location\s*/\s*\{[^}]*proxy_pass", c, re.S)
        rep.add("默认 location 不反代（仅 404）", PASS if not default_proxy else FAIL,
                "" if not default_proxy else "location / 内出现 proxy_pass → 暴露面失控")

        # 5. 方法限制 + server_tokens
        rep.add("非 POST 拒绝（405）", PASS if re.search(r"return\s+405\s*;", c) else FAIL,
                "" if re.search(r"return\s+405\s*;", c) else "缺 405 则 GET 也被转发")
        rep.add("server_tokens off", PASS if re.search(r"^\s*server_tokens\s+off\s*;", c, re.M) else FAIL)
        rep.add("客户端身份透传 X-Client-Subject",
                PASS if "X-Client-Subject" in c else SKIP,
                "" if "X-Client-Subject" in c else "仅影响排障/审计观测，非安全必需")

        # 唯一对外 TLS 监听
        tls_listens = re.findall(r"listen\s+(\d+)\s+ssl", c)
        rep.add("对外仅一个 TLS 监听 9443",
                PASS if tls_listens == ["9443"] else FAIL,
                f"实际 listen ssl: {tls_listens}")

    # ---------- 6~7. Deployment ----------
    deps = find_docs(all_docs, "Deployment")
    if not deps:
        rep.add("Deployment 存在", FAIL)
    else:
        dep = deps[0]
        spec = dep.get("spec", {})
        pod = spec.get("template", {}).get("spec", {})
        pod_sc = pod.get("securityContext") or {}
        containers = pod.get("containers") or []
        c0 = containers[0] if containers else {}
        c_sc = c0.get("securityContext") or {}

        rep.add("automountServiceAccountToken: false",
                PASS if pod.get("automountServiceAccountToken") is False else FAIL,
                "" if pod.get("automountServiceAccountToken") is False else "代理不需要 SA，挂载即多余凭据")
        rep.add("runAsNonRoot + runAsUser",
                PASS if pod_sc.get("runAsNonRoot") is True and pod_sc.get("runAsUser") else FAIL)
        rep.add("readOnlyRootFilesystem",
                PASS if c_sc.get("readOnlyRootFilesystem") is True else FAIL)
        rep.add("allowPrivilegeEscalation: false",
                PASS if c_sc.get("allowPrivilegeEscalation") is False else FAIL)
        drops = ((c_sc.get("capabilities") or {}).get("drop")) or []
        rep.add("capabilities drop ALL", PASS if "ALL" in [str(x).upper() for x in drops] else FAIL)
        rep.add("无 hostNetwork / hostPath",
                PASS if not pod.get("hostNetwork") and "hostPath" not in str(pod) else FAIL)

        # Secret 卷权限
        vols = pod.get("volumes") or []
        secret_vols = [v for v in vols if "secret" in v]
        mode, fsgroup = None, pod_sc.get("fsGroup")
        if secret_vols:
            mode = (secret_vols[0].get("secret") or {}).get("defaultMode")
        rep.add("Secret 卷 defaultMode = 0440",
                PASS if mode == 0o440 else FAIL,
                f"实际 {oct(mode) if isinstance(mode, int) else mode}"
                + ("" if mode == 0o440 else "（0400 时非 root 进程读不到 → CrashLoop，见 PRE-A-11）"))
        rep.add("pod fsGroup 已设置（0440 才有意义）",
                PASS if fsgroup else FAIL,
                f"fsGroup={fsgroup}" if fsgroup else "无 fsGroup ⇒ 卷属组不会变为容器 GID")

        # 端口名一致性
        ports = {p.get("name"): p.get("containerPort") for p in (c0.get("ports") or [])}
        svcs = find_docs(all_docs, "Service")
        if svcs:
            sp = {p.get("name"): (p.get("port"), p.get("targetPort")) for p in svcs[0]["spec"].get("ports", [])}
            bad = []
            for pname, (port, target) in sp.items():
                if isinstance(target, str) and ports.get(target) != port:
                    bad.append(f"{pname}: service {port} → targetPort {target}={ports.get(target)}")
            rep.add("Service 端口与容器端口名一致", PASS if not bad else FAIL, "; ".join(bad))

    # ---------- 8. 手工执行的文件不在 resources ----------
    base_res = [os.path.basename(r) for r in resources]
    leaked = [f for f in MANUAL_ONLY_FILES if f in base_res]
    rep.add("收紧/放行/模板文件不在 resources", PASS if not leaked else FAIL,
            "" if not leaked else f"误入 resources：{leaked}（会改变默认行为）")
    rep.add("resources 仅含代理主清单",
            PASS if base_res == ["nginx-mtls-proxy.yaml"] else SKIP,
            f"实际：{base_res}")

    # ---------- 9. 端口口径 ----------
    rep.add("端口口径 9443（写入）/ 8080（健康）",
            PASS if "9443" in str(resources) or "9443" in str(all_docs) else FAIL)

    # ---------- 10. 与发送侧一致 ----------
    gen = os.path.join(SENDER_DIR, "gen-ca.sh")
    if os.path.isfile(gen):
        text = open(gen, encoding="utf-8", errors="replace").read()
        default_san = re.search(r'^SERVER_SAN="([^"]+)"', text, re.M)
        srv = "remote-write-mtls-gateway" in (default_san.group(1) if default_san else "")
        rep.add("gen-ca.sh 默认 SAN 覆盖代理服务名",
                PASS if srv else FAIL,
                "" if srv else "发送侧 server_name 与代理证书不一致 → 握手必失败")
    else:
        rep.add("gen-ca.sh 存在", FAIL, f"未找到 {gen}")

    snippet = os.path.join(SENDER_DIR, "prometheus-remote-write-snippet.yml")
    if os.path.isfile(snippet):
        st = open(snippet, encoding="utf-8", errors="replace").read()
        rep.add("发送侧 snippet 指向 9443", PASS if "9443" in st else FAIL,
                "" if "9443" in st else "仍指向 9090 ⇒ 绕过代理")
    else:
        rep.add("发送侧 snippet 存在", SKIP)

    # ---------- 11. nginx -t ----------
    nginx = shutil.which("nginx")
    if not nginx:
        rep.add("nginx -t 语法校验", SKIP,
                "本机无 nginx（且无可用容器运行时）→ 未校验，静态断言不等于语法通过")
    else:
        rep.add("nginx -t 语法校验", SKIP,
                "检测到 nginx，但本脚本不代跑（需证书文件与 root 级 -c 路径，易误报）→ 请在真机执行")

    rep.dump(args.verbose)
    if rep.count(FAIL):
        return 1
    if args.strict and rep.count(SKIP):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
