#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P2-4 T-4.4 中央聚合部署资产自检脚本（也覆盖 T-1.10 overlay 的通用检查）。

检查项：
  1. YAML 可解析（逐文件、多文档）
  2. 明文凭据扫描（禁止 DSN/口令入库；模板文件与 REPLACE_ 占位符白名单放行）
  3. Grafana 看板 JSON 合法 + 必需变量 `cluster` 存在 + 表达式含 cluster 维度
  4. Alertmanager 配置含 cluster 维度（group_by 或 inhibit equal）
  5. 中央 Prometheus 开启 remote-write 接收（--web.enable-remote-write-receiver）
  6. promtool 规则语法校验（**本机无 promtool 时明确 SKIP，绝不假装通过**）

退出码语义：
  0 = 全部检查通过（SKIP 项会在报告中显式列出）
  1 = 存在 FAIL 项
  2 = 环境/输入错误（PyYAML 缺失、目录不存在、文件不可读等）

用法：
  python3 scripts/check-central-aggregation-assets.py
  python3 scripts/check-central-aggregation-assets.py --dir deploy/monitoring/central
  python3 scripts/check-central-aggregation-assets.py --promtool /usr/local/bin/promtool -v
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

try:
    import yaml
except ImportError:  # pragma: no cover - 环境依赖缺失
    sys.stderr.write(
        "FATAL: 缺少 PyYAML，无法执行 YAML 解析检查。"
        "请先安装依赖后重跑：python3 -m pip install pyyaml\n"
    )
    sys.exit(2)

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"

# 明文凭据扫描：postgres://user:pass@host 形态
CRED_RE = re.compile(r"(?:postgres(?:ql)?|mysql|mongodb)://[^\s\"']*:[^\s\"'@]+@")
# 白名单：模板文件 / 占位符
PLACEHOLDER_RE = re.compile(r"(REPLACE_[A-Z_]+|<user>|<pass>|<password>|\$\(|xxx+)", re.I)

DEFAULT_DIRS = [
    os.path.join("deploy", "monitoring", "central"),
    os.path.join("deploy", "monitoring-overlays", "remote-write-mtls"),
    os.path.join("deploy", "k8s-overlays", "multicluster"),
    os.path.join("deploy", "k8s-overlays", "trust"),
]


class Report:
    """检查结果收集器（按 PASS/FAIL/SKIP 计数）。"""

    def __init__(self, verbose: bool = False) -> None:
        self.rows: list[tuple[str, str, str]] = []  # (状态, 检查项, 说明)
        self.verbose = verbose

    def add(self, status: str, item: str, detail: str = "") -> None:
        self.rows.append((status, item, detail))
        if status != PASS or self.verbose:
            line = "[{}] {}{}".format(status, item, (" —— " + detail) if detail else "")
            print(line)

    def count(self, status: str) -> int:
        return sum(1 for r in self.rows if r[0] == status)

    @property
    def exit_code(self) -> int:
        return 1 if self.count(FAIL) > 0 else 0


def repo_root() -> str:
    """返回仓库根目录（脚本位于 <root>/scripts/ 下）。"""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def yaml_files(directory: str) -> list[str]:
    """列出目录下所有 yaml/yml 资产文件（含 `*.example` 后缀的模板，排序保证输出稳定）。"""
    pats = [
        os.path.join(directory, "*.yaml"),
        os.path.join(directory, "*.yml"),
        os.path.join(directory, "*.example"),
    ]
    files: list[str] = []
    for p in pats:
        files.extend(glob.glob(p))
    return sorted(set(files))


def load_docs(path: str) -> list[object]:
    """解析一个 YAML 文件的全部文档。"""
    with open(path, "r", encoding="utf-8") as fh:
        return [d for d in yaml.safe_load_all(fh) if d is not None]


def check_yaml_parse(directory: str, rep: Report) -> None:
    """检查项 1：所有 YAML 文件可解析。"""
    files = yaml_files(directory)
    if not files:
        rep.add(FAIL, "yaml: {} 下无 yaml 文件".format(directory), "目录为空或路径错误")
        return
    for f in files:
        try:
            docs = load_docs(f)
        except Exception as exc:  # noqa: BLE001 - 需把解析错误报给用户
            rep.add(FAIL, "yaml 解析: {}".format(f), str(exc))
            continue
        rep.add(PASS, "yaml 解析: {}（{} 个文档）".format(f, len(docs)))


def check_credentials(directory: str, rep: Report) -> None:
    """检查项 2：禁止明文凭据入库（模板/占位符放行）。"""
    for f in yaml_files(directory):
        try:
            text = open(f, "r", encoding="utf-8").read()
        except OSError as exc:
            rep.add(FAIL, "凭据扫描读取: {}".format(f), str(exc))
            continue
        hits = [m for m in CRED_RE.findall(text) if not PLACEHOLDER_RE.search(m)]
        is_template = ".example." in os.path.basename(f) or f.endswith(".example.yaml")
        if hits and not is_template:
            rep.add(FAIL, "凭据扫描: {}".format(f), "发现明文凭据: {}".format(hits[:2]))
        elif hits and is_template:
            rep.add(
                SKIP,
                "凭据扫描: {}".format(f),
                "模板文件命中占位符形态（{}），已白名单放行".format(hits[:1]),
            )
        else:
            rep.add(PASS, "凭据扫描: {}".format(f), "无明文凭据")


def check_dashboards(directory: str, rep: Report) -> None:
    """检查项 3：看板 JSON 合法 + cluster 变量 + cluster 维度表达式。"""
    found = 0
    for f in yaml_files(directory):
        try:
            docs = load_docs(f)
        except Exception:  # noqa: BLE001 - 解析失败已在检查项 1 报告
            continue
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            if doc.get("kind") != "ConfigMap":
                continue
            data = doc.get("data") or {}
            for key, raw in data.items():
                if not str(key).endswith(".json"):
                    continue
                found += 1
                item = "看板 JSON: {}#{}".format(os.path.basename(f), key)
                try:
                    dash = json.loads(raw)
                except Exception as exc:  # noqa: BLE001
                    rep.add(FAIL, item, "JSON 非法: {}".format(exc))
                    continue
                if not isinstance(dash, dict) or "panels" not in dash:
                    rep.add(SKIP, item, "非看板 JSON（无 panels 段），仅校验 JSON 合法性")
                    continue
                rep.add(PASS, item, "JSON 合法（title={}）".format(dash.get("title", "?")))
                # 必需变量 cluster
                names = [
                    v.get("name")
                    for v in (dash.get("templating", {}).get("list") or [])
                    if isinstance(v, dict)
                ]
                if "cluster" in names:
                    rep.add(PASS, item + " 变量", "模板变量 cluster 存在")
                else:
                    rep.add(FAIL, item + " 变量", "缺少模板变量 cluster（口径：统一用 cluster）")
                # 表达式含 cluster 维度
                exprs: list[str] = []
                for p in dash.get("panels", []) or []:
                    for t in (p.get("targets") or []):
                        if isinstance(t, dict) and t.get("expr"):
                            exprs.append(str(t["expr"]))
                if any("cluster" in e for e in exprs):
                    rep.add(PASS, item + " 维度", "面板表达式含 cluster 维度")
                else:
                    rep.add(FAIL, item + " 维度", "所有表达式均未使用 cluster 标签")
    if found == 0:
        rep.add(SKIP, "看板 JSON: {}".format(directory), "该目录无 *.json 看板资产")


def check_embedded_yaml(directory: str, rep: Report) -> None:
    """检查项 1b：ConfigMap 内嵌的 YAML 文本可解析（prometheus.yml / rules 等）。

    外层的 `yaml 解析` 只校验文件本身；内嵌配置是**字符串**，必须单独解析，
    否则缩进/语法错误会一直潜伏到集群里才暴露。
    """
    found = 0
    for f in yaml_files(directory):
        try:
            docs = load_docs(f)
        except Exception:  # noqa: BLE001 - 解析失败已在检查项 1 报告
            continue
        for doc in docs:
            if not isinstance(doc, dict) or doc.get("kind") != "ConfigMap":
                continue
            for key, raw in (doc.get("data") or {}).items():
                if not str(key).endswith((".yml", ".yaml")):
                    continue
                found += 1
                item = "内嵌 YAML: {}#{}".format(os.path.basename(f), key)
                try:
                    parsed = yaml.safe_load(raw)
                except Exception as exc:  # noqa: BLE001
                    rep.add(FAIL, item, "解析失败: {}".format(exc))
                    continue
                if parsed is None:
                    rep.add(FAIL, item, "内嵌配置为空")
                    continue
                rep.add(PASS, item, "可解析（顶层键: {}）".format(
                    sorted(parsed.keys()) if isinstance(parsed, dict) else type(parsed).__name__
                ))


def walk_dicts(node: object):
    """递归遍历任意 YAML 结构中的所有 dict（用于定位 env/args 片段）。"""
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from walk_dicts(v)
    elif isinstance(node, list):
        for v in node:
            yield from walk_dicts(v)


def check_secret_reference(directory: str, rep: Report) -> None:
    """检查项 7：导出端点凭证/白名单必须经 Secret / ConfigMap 引用（禁明文与默认写死）。

    - `*AUDIT_EXPORT_TOKEN`  → 必须 valueFrom.secretKeyRef（令牌不得写在清单里）
    - `*AUDIT_EXPORT_CIDRS`  → 必须 valueFrom.configMapKeyRef（白名单来源可追溯、可运维替换）
    """
    found = 0
    for f in yaml_files(directory):
        try:
            docs = load_docs(f)
        except Exception:  # noqa: BLE001
            continue
        for doc in docs:
            for d in walk_dicts(doc):
                name = d.get("name")
                if not isinstance(name, str):
                    continue
                vf = d.get("valueFrom")
                if not isinstance(vf, dict):
                    continue
                if "AUDIT_EXPORT_TOKEN" in name:
                    found += 1
                    if "secretKeyRef" in vf:
                        rep.add(PASS, "凭证引用: {}#{}".format(os.path.basename(f), name), "经 secretKeyRef")
                    else:
                        rep.add(FAIL, "凭证引用: {}#{}".format(os.path.basename(f), name), "令牌未走 Secret 引用")
                elif "AUDIT_EXPORT_CIDRS" in name:
                    found += 1
                    if "configMapKeyRef" in vf:
                        rep.add(PASS, "白名单引用: {}#{}".format(os.path.basename(f), name), "经 configMapKeyRef")
                    else:
                        rep.add(FAIL, "白名单引用: {}#{}".format(os.path.basename(f), name), "CIDR 白名单未走 ConfigMap 引用")
    if found == 0:
        rep.add(SKIP, "凭证引用: {}".format(directory), "该目录无导出端点开关引用（不适用）")


def check_remote_write_endpoint(directory: str, rep: Report) -> None:
    """检查项 8：remote_write 目标地址必须可配置（占位符），禁止写死内网地址。

    口径：中央侧落地形态由客户环境决定（客户既有 Prometheus 或我方交付的 central 栈），
    两者地址不同 → 资产中只能留占位符 `REPLACE_WITH_CENTRAL_WRITE_ENDPOINT`。
    """
    found = 0
    for f in yaml_files(directory) + [
        os.path.join(directory, "prometheus-remote-write-snippet.yml")
    ]:
        if not os.path.isfile(f):
            continue
        try:
            text = open(f, "r", encoding="utf-8").read()
        except OSError:
            continue
        if "remote_write" not in text:
            continue
        found += 1
        urls = re.findall(r"url:\s*[\"']?([^\"'\n]+)", text)
        hardcoded = [u.strip() for u in urls if "REPLACE_WITH" not in u and "prometheus-central" in u]
        placeholder = [u.strip() for u in urls if "REPLACE_WITH" in u]
        if hardcoded:
            rep.add(
                FAIL,
                "remote_write 地址: {}".format(os.path.basename(f)),
                "写死了内网地址: {}".format(hardcoded[:2]),
            )
        elif placeholder:
            rep.add(PASS, "remote_write 地址: {}".format(os.path.basename(f)), "占位符可配置: {}".format(placeholder[:1]))
        else:
            rep.add(SKIP, "remote_write 地址: {}".format(os.path.basename(f)), "未见 remote_write url（不适用）")
    if found == 0:
        rep.add(SKIP, "remote_write 地址: {}".format(directory), "该目录无 remote_write 配置")


def check_alertmanager(directory: str, rep: Report) -> None:
    """检查项 4：Alertmanager 配置含 cluster 维度（group_by / inhibit equal）。"""
    found = 0
    for f in yaml_files(directory):
        try:
            docs = load_docs(f)
        except Exception:  # noqa: BLE001
            continue
        for doc in docs:
            if not isinstance(doc, dict) or doc.get("kind") != "ConfigMap":
                continue
            for key, raw in (doc.get("data") or {}).items():
                if "alertmanager" not in str(key):
                    continue
                found += 1
                item = "Alertmanager: {}#{}".format(os.path.basename(f), key)
                try:
                    cfg = yaml.safe_load(raw)
                except Exception as exc:  # noqa: BLE001
                    rep.add(FAIL, item, "内嵌配置解析失败: {}".format(exc))
                    continue
                rep.add(PASS, item, "内嵌配置可解析")
                route = (cfg or {}).get("route", {}) or {}
                groups: list[list[str]] = [list(route.get("group_by") or [])]
                for r in route.get("routes", []) or []:
                    groups.append(list((r or {}).get("group_by") or []))
                inhibits = (cfg or {}).get("inhibit_rules", []) or []
                equals: list[list[str]] = [
                    list((i or {}).get("equal") or []) for i in inhibits
                ]
                has_cluster = any("cluster" in g for g in groups) or any(
                    "cluster" in e for e in equals
                )
                if has_cluster:
                    rep.add(PASS, item + " cluster 维度", "group_by/inhibit equal 含 cluster")
                else:
                    rep.add(
                        FAIL,
                        item + " cluster 维度",
                        "group_by 与 inhibit equal 均无 cluster，无法实现按集群去重/抑制",
                    )
    if found == 0:
        rep.add(SKIP, "Alertmanager: {}".format(directory), "该目录无 alertmanager 配置")


def check_remote_write_receiver(directory: str, rep: Report) -> None:
    """检查项 5：中央 Prometheus 开启 remote-write 接收。"""
    found = 0
    for f in yaml_files(directory):
        try:
            docs = load_docs(f)
        except Exception:  # noqa: BLE001
            continue
        for doc in docs:
            if not isinstance(doc, dict) or doc.get("kind") != "Deployment":
                continue
            name = str((doc.get("metadata") or {}).get("name", ""))
            if "prometheus" not in name or "central" not in name:
                continue
            found += 1
            item = "remote-write 接收: Deployment/{}".format(name)
            containers = (
                ((doc.get("spec") or {}).get("template") or {})
                .get("spec", {})
                .get("containers", [])
                or []
            )
            args: list[str] = []
            for c in containers:
                args.extend([str(a) for a in (c.get("args") or [])])
            if "--web.enable-remote-write-receiver" in args:
                rep.add(PASS, item, "已开启 --web.enable-remote-write-receiver")
            else:
                rep.add(FAIL, item, "未开启 remote-write 接收端点")
    if found == 0:
        rep.add(SKIP, "remote-write 接收: {}".format(directory), "该目录无中央 Prometheus Deployment")


def extract_rule_files(directory: str) -> list[tuple[str, object]]:
    """抽取可交给 promtool 校验的规则组。

    支持两种形态：
      * 原生栈：ConfigMap data 中以 .rules.yml/.rules.yaml 结尾的键（值为规则文本）
      * Operator 栈：PrometheusRule CR 的 spec.groups
    返回 [(来源名, groups 结构)]。
    """
    out: list[tuple[str, object]] = []
    for f in yaml_files(directory):
        try:
            docs = load_docs(f)
        except Exception:  # noqa: BLE001
            continue
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind")
            if kind == "ConfigMap":
                for key, raw in (doc.get("data") or {}).items():
                    if str(key).endswith((".rules.yml", ".rules.yaml")):
                        out.append(("{}#{}".format(os.path.basename(f), key), raw))
            elif kind == "PrometheusRule":
                groups = ((doc.get("spec") or {}).get("groups")) or []
                out.append(("{}#{}".format(os.path.basename(f), "spec.groups"), groups))
    return out


def find_promtool(explicit: str = "") -> str:
    """定位 promtool：显式路径 > PATH > 常见安装位置。未找到返回空串。"""
    if explicit:
        return explicit if os.path.isfile(explicit) else ""
    found = shutil.which("promtool")
    if found:
        return found
    for cand in ("/usr/local/bin/promtool", "/usr/bin/promtool", "/opt/prometheus/promtool"):
        if os.path.isfile(cand):
            return cand
    return ""


def check_promtool(directory: str, rep: Report, promtool: str) -> None:
    """检查项 6：promtool 规则语法校验（无 promtool → 明确 SKIP）。"""
    rules = extract_rule_files(directory)
    if not rules:
        rep.add(SKIP, "promtool: {}".format(directory), "该目录无可校验的规则资产")
        return
    tool = find_promtool(promtool)
    if not tool:
        rep.add(
            SKIP,
            "promtool 规则语法: {}".format(directory),
            "本机未安装 promtool（也未通过 --promtool 指定）→ **未做规则语法校验**，"
            "待环境就绪后重跑本脚本（沿用既有 promtool 校验惯例）",
        )
        return
    tmpdir = tempfile.mkdtemp(prefix="p24-promtool-")
    try:
        for idx, (src, payload) in enumerate(rules):
            path = os.path.join(tmpdir, "rules-{}.yml".format(idx))
            if isinstance(payload, str):
                text = payload
            else:
                text = yaml.safe_dump({"groups": payload}, allow_unicode=True, sort_keys=False)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            proc = subprocess.run(
                [tool, "check", "rules", path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            if proc.returncode == 0:
                rep.add(PASS, "promtool 规则语法: {}".format(src), "check rules 通过")
            else:
                rep.add(FAIL, "promtool 规则语法: {}".format(src), proc.stdout.strip()[:400])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="P2-4 T-4.4 中央聚合部署资产自检（含 T-1.10 overlay 通用检查）"
    )
    parser.add_argument(
        "--dir",
        action="append",
        default=[],
        help="待检查目录（相对仓库根，可重复）；默认检查 {}".format(DEFAULT_DIRS),
    )
    parser.add_argument("--promtool", default="", help="promtool 可执行文件路径（可选）")
    parser.add_argument("-v", "--verbose", action="store_true", help="输出全部 PASS 明细")
    args = parser.parse_args(argv)

    root = repo_root()
    dirs = args.dir or DEFAULT_DIRS
    abs_dirs = [d if os.path.isabs(d) else os.path.join(root, d) for d in dirs]

    rep = Report(verbose=args.verbose)
    print("=" * 78)
    print("P2-4 部署资产自检（T-4.4 中央聚合 / T-1.10 overlay）")
    print("仓库根: {}".format(root))
    print("检查目录: {}".format(", ".join(dirs)))
    print("=" * 78)

    for d in abs_dirs:
        if not os.path.isdir(d):
            sys.stderr.write("FATAL: 目录不存在: {}\n".format(d))
            return 2
        label = os.path.relpath(d, root)
        print("\n---- {} ----".format(label))
        check_yaml_parse(d, rep)
        check_embedded_yaml(d, rep)
        check_credentials(d, rep)
        check_dashboards(d, rep)
        check_alertmanager(d, rep)
        check_remote_write_receiver(d, rep)
        check_secret_reference(d, rep)
        check_remote_write_endpoint(d, rep)
        check_promtool(d, rep, args.promtool)

    print("\n" + "=" * 78)
    print(
        "汇总: PASS={} FAIL={} SKIP={}".format(
            rep.count(PASS), rep.count(FAIL), rep.count(SKIP)
        )
    )
    if rep.count(SKIP) > 0:
        print("以下项为 SKIP（**未校验**，不得视为通过）：")
        for status, item, detail in rep.rows:
            if status == SKIP:
                print("  - {} —— {}".format(item, detail))
    print("=" * 78)
    return rep.exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
