#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
doc-audit.py — GA 文档体系机检脚本（《GA-文档体系规范》v2.0 §8）

规则：
  R01 根逃逸   仓库根存在 *.md（仅 README.md 白名单）           error
  R02 孤儿     L3/L4 文档未被任何文档引用                        error
  R03 悬空链接 markdown 相对链接目标不存在                       error
  R04 头部     L3/L4 缺「文档性质/状态/本体」三字段或本体不存在  error
  R05 评审轮次 同族评审报告 >=4 轮 error；=3 轮 warn
  R06 地图新鲜 L2 本体未登记进《项目总览与路线图》§9            error
  R07 疑似重复 标题归一化相似 >0.85，或同前缀族 >6 个           warn
  R08 应归档   头部声明"已归档"却仍在活跃目录                   warn
  R09 违禁表述 命中废止短语黑名单                                error

用法：
  python scripts/doc-audit.py                 全量审计；有 error 退 1
  python scripts/doc-audit.py --find-dup 关键词  新建文档前查重
"""

import argparse
import difflib
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# ---------- 常量配置（集中维护，追加即可） ----------

ROOT_MD_WHITELIST = {"README.md"}

# L1 项目级标准文档与排期分册（按 basename）：不参与 R02/R04/R06 判定
L1_BASENAMES = {
    "GA-部署指南.md",
    "API-参考.md",
    "GA-用户手册.md",
    "GA-产品场景与可信区域矩阵.md",
    "GA-项目总览与路线图.md",
    "GA-文档体系规范.md",
    "GA-报备与上线放行单模板.md",
    "GA-AI网关能力补齐--研发计划与进度跟踪.md",
    "GA-网关功能面研发计划.md",
    "GA-输出侧内容审查-研发计划.md",
}
MAP_BASENAME = "GA-项目总览与路线图.md"

# L3/L4 文件名特征（命中其一即按过程件要求头部三字段）
L3L4_KEYWORDS = [
    "评审", "决策材料", "处置记录", "验收", "报告", "Runbook", "runbook",
    "SOP", "演练", "浸泡", "标定", "基准", "操作手册", "运维手册", "手册",
    "操作单", "准备包", "留证", "台账", "摸底", "评测", "清单", "模板",
    "说明", "跟踪", "规格", "计划",
]
# L2 本体强制覆盖：文件名含 L3/L4 关键词、但实为设计本体（不该被要求三字段）
L2_FORCE = {
    "GA-AI网关能力补齐方案--P0--侧信道风险披露说明.md",
    "GA-AI网关能力补齐方案--P2--行业解决方案模板.md",
}

# R05：评审轮次
ROUND_RE = re.compile(r"第\s*([\d.]+)\s*轮")
# 作用于 stem（无扩展名）：吃掉 "-多角色评审报告-第N轮[-定向评审]" 等后缀
FAMILY_STRIP_RE = re.compile(r"[-—]?(多角色评审报告|评审响应与处置记录)?[-—]?第\s*[\d.]+\s*轮.*$")

# R09：废止短语黑名单（每条注明替代口径）
FORBIDDEN = [
    ("内网可信", '已废止信任假设，现行口径"除 TEE 飞地外皆不可信"（见场景与可信区域矩阵）'),
    ("isReady", 'ioredis 连接就绪判断必须用 status === "ready"，不得用 isReady'),
]
# 行内豁免：出现该标记，或命中行同时含"变更记录/元引述"语境词，则该行跳过 R09
IGNORE_MARK = "doc-audit-ignore"
META_CONTEXT_RE = re.compile(r"已改|已按|修订|变更|改为|废止|作废|普遍化|审计|历史|原表述|旧口径|修正为")

# R07：已人工裁定为"非重复"的文档对（规范 §5.4），按 basename 无序对登记
R07_ACCEPTED_PAIRS = {
    # 本体（方案设计）↔ 分册（M2 细化方案）
    frozenset({"管理门户-apiTokens-Secret化方案设计.md", "管理门户-apiTokens-Secret化-M2细化方案.md"}),
    # 能力本体（P1-1）↔ P2 实施任务书（P2-1；文件名为研发计划 §10 规定，分工声明见两侧头部）
    frozenset({"GA-AI网关能力补齐方案--P1--MCP协议网关.md", "GA-AI网关能力补齐方案--P2--MCP协议网关化.md"}),
}

SKIP_DIRS = {".git", "node_modules", "vendor", ".trae", "html-snapshots", "_shared", "assets"}

LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
H1_RE = re.compile(r"^#\s+(.+?)\s*$", re.M)
HEAD_FIELD_RE = re.compile(r"\*\*(文档性质|状态|本体)\*\*")
TITLE_NOISE_RE = re.compile(r"[（(].*?[)）]|v?\d+(?:\.\d+)+|\d{4}-\d{2}-\d{2}|第?\d+轮|[\s\-—_·:：,，。；;、]+")


# ---------- 数据结构 ----------

@dataclass
class Finding:
    rule: str
    level: str  # "error" | "warn"
    path: Path
    msg: str

    def rel(self, root: Path) -> str:
        try:
            return str(self.path.relative_to(root))
        except ValueError:
            return str(self.path)


# ---------- 基础工具 ----------

def find_md_files(root: Path):
    """受管 md = 仓库根 *.md + docs/**/*.md（规范适用范围）；跳过快照资产目录。"""
    files = list(root.glob("*.md"))
    docs = root / "docs"
    if docs.is_dir():
        for p in docs.rglob("*.md"):
            if not (set(p.relative_to(root).parts[:-1]) & SKIP_DIRS):
                files.append(p)
    return sorted(set(files), key=lambda x: str(x).lower())


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return ""


def is_archive(path: Path, root: Path) -> bool:
    return "archive" in path.relative_to(root).parts


def is_l3l4(path: Path) -> bool:
    name = path.name
    if name in L2_FORCE:
        return False
    return any(k in name for k in L3L4_KEYWORDS)


def extract_links(text: str):
    """返回 [(原始目标, 行号)]，仅相对链接（过滤 http/锚点/mailto/行内代码示例）。"""
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        for m in LINK_RE.finditer(line):
            target = m.group(1).strip()
            if target.startswith(("http://", "https://", "mailto:", "tel:", "#")):
                continue
            if line[:m.start()].count("`") % 2 == 1:
                continue  # 链接位于行内代码 span 内（语法示例）
            out.append((target, i))
    return out


def link_target_exists(base_file: Path, target: str) -> bool:
    clean = target.split("#", 1)[0].split("?", 1)[0]
    if not clean:
        return True  # 纯锚点链接
    return (base_file.parent / clean).resolve().exists()


def normalize_title(title: str) -> str:
    return TITLE_NOISE_RE.sub("", title).lower()


def family_key(name: str) -> str:
    return FAMILY_STRIP_RE.sub("", name)


# ---------- 各规则检查 ----------

def check_r01(root: Path):
    findings = []
    for p in sorted(root.glob("*.md")):
        if p.name not in ROOT_MD_WHITELIST:
            findings.append(Finding("R01", "error", p, "仓库根下的项目文档必须移入 docs/（仅 README.md 豁免）"))
    return findings


def check_r02_r04_r08(root: Path, files, referenced_basenames: set, map_text: str):
    findings = []
    for p in files:
        if is_archive(p, root) or p.name in L1_BASENAMES or p.name == MAP_BASENAME:
            continue
        text = read_text(p)
        head = "\n".join(text.splitlines()[:20])
        l3l4 = is_l3l4(p)

        # R02 孤儿：过程件 / 子域文档必须被某处引用
        if l3l4 and p.name not in referenced_basenames:
            findings.append(Finding("R02", "error", p, "未被任何文档引用（孤儿）；须在 L1 对应章节或 §9 地图登记"))

        # R04 头部三字段
        if l3l4:
            missing = [k for k in ("文档性质", "状态", "本体") if not re.search(r"\*\*" + k + r"\*\*", head)]
            if missing:
                findings.append(Finding("R04", "error", p, f"头部前 20 行缺字段：{'/'.join(missing)}"))
            else:
                pointer = extract_body_pointer(head)
                if pointer:
                    clean = pointer.split("#", 1)[0]
                    if clean and not (p.parent / clean).resolve().exists():
                        findings.append(Finding("R04", "error", p, f"本体指针目标不存在：{pointer}"))

        # R08 已归档但滞留活跃目录
        if re.search(r"\*\*状态\*\*[：:]\s*已归档", head) and not is_archive(p, root):
            findings.append(Finding("R08", "warn", p, "头部声明已归档，却仍在活跃目录；应移入 archive/"))
    return findings


def check_r03(root: Path, files):
    findings = []
    for p in files:
        if is_archive(p, root):
            continue
        text = read_text(p)
        for target, lineno in extract_links(text):
            if target.startswith("file:"):
                findings.append(Finding("R03", "error", p,
                                        f"L{lineno} 使用本机绝对链接 file:// …，换机即失效；须改为仓库相对链接"))
            elif not link_target_exists(p, target):
                findings.append(Finding("R03", "error", p, f"L{lineno} 悬空链接：{target}"))
    return findings


def check_r05(root: Path, files):
    findings = []
    families = {}
    for p in files:
        if is_archive(p, root):
            continue
        m = ROUND_RE.search(p.name)
        if not m:
            continue
        key = family_key(p.stem)
        families.setdefault(key, []).append((m.group(1), p))
    for key, items in families.items():
        labels = sorted(r for r, _ in items)
        top = max(items, key=lambda x: float(x[0]))[1]
        if len(labels) >= 4:
            findings.append(Finding("R05", "error", top,
                                    f"同族评审报告已 {len(labels)} 轮（{labels}）；第 4 轮起禁止新建，前序应归档、保留唯一处置记录"))
        elif len(labels) == 3:
            findings.append(Finding("R05", "warn", top, "同族评审报告已 3 轮；再评须改为追加处置记录"))
    return findings


def check_r06(root: Path, files, map_text: str):
    findings = []
    for p in files:
        if is_archive(p, root) or not re.search(r"详细设计.P\d", p.relative_to(root).as_posix()):
            continue
        if is_l3l4(p) or p.name in L1_BASENAMES:
            continue
        if p.name not in map_text:
            findings.append(Finding("R06", "error", p, "L2 本体未登记进《GA-项目总览与路线图》§9 文档地图"))
    return findings


def check_r07(root: Path, files):
    findings = []
    titled = []
    families = {}
    for p in files:
        if is_archive(p, root):
            continue
        text = read_text(p)
        m = H1_RE.search(text)
        if m and not is_l3l4(p):
            # 标题相似度只比本体/标准类文档；过程件标题天然雷同，不参与
            titled.append((p, normalize_title(m.group(1))))
        key = family_key(p.stem)
        families.setdefault(key, []).append(p)

    seen_pairs = set()
    for i in range(len(titled)):
        for j in range(i + 1, len(titled)):
            (p1, t1), (p2, t2) = titled[i], titled[j]
            if not t1 or not t2 or abs(len(t1) - len(t2)) > max(len(t1), len(t2)) * 0.5:
                continue
            ratio = difflib.SequenceMatcher(None, t1, t2).ratio()
            if ratio > 0.85 and frozenset({p1.name, p2.name}) not in R07_ACCEPTED_PAIRS:
                sig = tuple(sorted((str(p1), str(p2))))
                if sig not in seen_pairs:
                    seen_pairs.add(sig)
                    findings.append(Finding("R07", "warn", p1,
                                            f"标题与《{p2.name}》相似度 {ratio:.2f}（{p1.name} ↔ {p2.name}）；须分工声明或合并"))
    for key, members in families.items():
        if len(members) > 6:
            findings.append(Finding("R07", "warn", members[0],
                                    f"同前缀文档族 {len(members)} 个（主干：{key}）；确认是否应章节化/归档"))
    return findings


def check_r09(root: Path, files):
    findings = []
    for p in files:
        if is_archive(p, root):
            continue
        text = read_text(p)
        for i, line in enumerate(text.splitlines(), 1):
            if IGNORE_MARK in line or META_CONTEXT_RE.search(line):
                continue
            for phrase, hint in FORBIDDEN:
                if phrase in line:
                    findings.append(Finding("R09", "error", p, f"L{i} 命中废止表述「{phrase}」→ {hint}"))
    return findings


# ---------- 主流程 ----------

def build_reference_index(files):
    """全局引用索引：文件名（含或不含 .md）在其他 md 文本中出现即视为被引用。"""
    referenced = set()
    for p in files:
        text = read_text(p)
        for q in files:
            if q == p:
                continue
            if q.name in text or q.stem in text:
                referenced.add(q.name)
    return referenced


def extract_body_pointer(head: str):
    """从头部提取本体指针：优先 markdown 链接的 URL，否则取裸路径。"""
    m = re.search(r"\*\*本体\*\*[：:]\s*(.+)", head)
    if not m:
        return None
    raw = m.group(1).strip()
    link = re.search(r"\[[^\]]*\]\(([^)#]+)(?:#[^)]*)?\)", raw)
    if link:
        return link.group(1).strip()
    return raw.split()[0].strip("`()（），,。；;")


def run_audit(root: Path):
    files = find_md_files(root)
    map_path = root / "docs" / MAP_BASENAME
    map_text = read_text(map_path) if map_path.exists() else ""
    referenced = build_reference_index(files)

    findings = []
    findings += check_r01(root)
    findings += check_r02_r04_r08(root, files, referenced, map_text)
    findings += check_r03(root, files)
    findings += check_r05(root, files)
    findings += check_r06(root, files, map_text)
    findings += check_r07(root, files)
    findings += check_r09(root, files)
    return findings


def find_dup(root: Path, keyword: str):
    files = find_md_files(root)
    kw = keyword.lower()
    hits = []
    for p in files:
        if kw in p.name.lower():
            text = read_text(p)
            m = H1_RE.search(text)
            hits.append((p.relative_to(root), m.group(1) if m else "(无一级标题)"))
    print(f"关键词「{keyword}」命中文档 {len(hits)} 个：")
    for rel, title in hits:
        print(f"  {rel}  ==>  {title}")
    if not hits:
        print("（无同名/近似文档，可按出生卡新建）")
    return 0


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(description="GA 文档体系机检（规范 v2.0 §8）")
    ap.add_argument("--root", default=None, help="仓库根（默认脚本上级目录）")
    ap.add_argument("--find-dup", metavar="关键词", help="新建文档前按文件名关键词查重")
    args = ap.parse_args()

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parent.parent
    if not (root / "docs").is_dir():
        print(f"无法定位仓库根（缺 docs/）：{root}", file=sys.stderr)
        return 2

    if args.find_dup:
        return find_dup(root, args.find_dup)

    findings = run_audit(root)
    order = ["R01", "R02", "R03", "R04", "R05", "R06", "R07", "R08", "R09"]
    errors = [f for f in findings if f.level == "error"]
    warns = [f for f in findings if f.level == "warn"]

    for rule in order:
        group = [f for f in findings if f.rule == rule]
        if not group:
            continue
        print(f"\n=== {rule}（{len(group)}）===")
        for f in sorted(group, key=lambda x: (x.level != "error", x.rel(root))):
            tag = "ERROR" if f.level == "error" else "warn "
            print(f"[{tag}] {f.rel(root)}\n        {f.msg}")

    print(f"\n=== 汇总：error={len(errors)}  warn={len(warns)} ===")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
