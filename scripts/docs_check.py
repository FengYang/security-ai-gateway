#!/usr/bin/env python3
"""docs_check.py — 跨文档一致性校验工具（只读校验器）。

【项目本地口径适配 · M1-2 / R-10】本文件为共享 IPD 技能包 docs_check.py 的**项目本地副本**，
不修改共享技能包（避免影响其它项目）。唯一改动：DEF_PATTERN 第二分支容忍
「表格单元格内加粗编号」`| **FR-7** |` 形态——归档需求清单
`docs/archive/OTP-Mask安全聚合组件-需求清单.md` 中 FR-7..FR-21 的定义均为此形态，
原正则 `^\|\s*ID\s*\|` 无法识别，导致 15 条**真实定义**被误判为孤儿（假性孤儿）。
口径依据见 `docs/路线2-剩余裁决阻断-待评审提案.md` §「B 工具 ID 口径适配」（首选方案）；
**不删除任何真实引用、不裁剪基线**，TR/Q 不参与孤儿判定与 EXEMPT_REFS 等既有口径全部保留。

用法:
    python docs_check.py scan [docs_dir] [--report json|text]
    python docs_check.py check <id> [docs_dir]     # 检查单个 ID 的定义与引用
    python docs_check.py --self-test

校验规则:
    1. 从 docs/ 目录提取 ID 编号（FR-/NFR-/CR-/CC-/RISK-/TR-/Q-）
    2. 检查跨文档引用完整性:
       - 孤儿引用: 被引用但无定义（在任何文档中找不到定义行）
       - 遗漏引用: 有定义但从未被引用
       - 版本冲突: 同一文档在不同处引用的版本号不一致
    3. 输出一致性报告

退出码:
    0 = 一致, 1 = 发现不一致, 2 = 用法错误
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# ID 模式: FR-001 / NFR-012 / CR-003 / CC-01 / RISK-005 / TR4 / Q12
# 注意: 不能用 \b（中文字符被当作 word 字符），改用前后否定断言
ID_PATTERNS = {
    "FR": r"(?<![A-Za-z0-9-])FR-(\d{1,3})(?![0-9])",
    "NFR": r"(?<![A-Za-z0-9-])NFR-(\d{1,3})(?![0-9])",
    "CR": r"(?<![A-Za-z0-9-])CR-(\d{1,3})(?![0-9])",
    "CC": r"(?<![A-Za-z0-9-])CC-(\d{1,2})(?![0-9])",
    "RISK": r"(?<![A-Za-z0-9-])RISK-(\d{1,3})(?![0-9])",
    "TR": r"(?<![A-Za-z0-9-])TR([1-6])(?![0-9])",
    "Q": r"(?<![A-Za-z0-9-])Q(\d{1,2})(?![0-9])",
}

# 只有"需求类"ID 需要定义行；TR1-6（技术评审门）、Q1-12（质量属性）是 IPD 方法论术语，
# 全流程引用但无逐条"定义"，不参与孤儿判定（避免将 TR1-TR6 误报为孤儿）
REQUIREMENT_PREFIXES = {"FR", "NFR", "CR", "CC", "RISK"}

# 已知"分析性元引用"豁免：评估结论 .md 中刻意用 "check FR-001 无定义判一致" 等句式
# 证明本工具的假阴性缺陷，属有意元引用而非真实需求缺口；列入豁免避免误报阻断文档门。
# 若未来真有 FR-1 需求，请在此移除并补定义行。
EXEMPT_REFS = {"FR-1"}

# 定义模式: 行首或标题中含 ID（如 "### FR-001" 或 "| FR-001 |"）。
# M1-2/R-10 本地适配：第二分支容忍 `| **FR-7** |` 加粗单元格编号，
# 用 \b 边界替代「编号后必须紧跟 |」，避免把归档清单的真实定义判成假性孤儿。
DEF_PATTERN = re.compile(
    r"^#{0,4}\s*(?:\*\*)?((?:FR|NFR|CR|CC|RISK)-\d{1,3}|TR[1-6]|Q\d{1,2})\b"
    r"|^\|\s*(?:\*\*)?((?:FR|NFR|CR|CC|RISK)-\d{1,3}|TR[1-6]|Q\d{1,2})\b",
    re.MULTILINE,
)

# 版本号模式
VERSION_PATTERN = re.compile(r"V(\d+\.\d+(?:\.\d+)?)")

DEFAULT_DOCS_DIR = "docs"


def extract_ids(text: str) -> dict[str, set[str]]:
    """从文本中提取各类 ID 编号。"""
    result = {}
    for prefix, pattern in ID_PATTERNS.items():
        matches = re.findall(pattern, text)
        if prefix in ("TR", "Q"):
            result[prefix] = set(f"{prefix}{m}" for m in matches)
        else:
            result[prefix] = set(f"{prefix}-{m}" for m in matches)
    return result


def extract_definitions(text: str) -> set[str]:
    """从文本中提取定义的 ID（标题或表格行首）。"""
    ids = set()
    for m in DEF_PATTERN.finditer(text):
        val = m.group(1) or m.group(2)
        if val:
            # 标准化: FR-01 -> FR-1, TR4 -> TR4
            parts = val.replace("--", "-").split("-") if "-" in val else [val]
            if len(parts) == 2:
                ids.add(f"{parts[0]}-{int(parts[1])}")
            else:
                ids.add(val)
    return ids


def normalize_id(raw: str) -> str:
    """标准化 ID: FR-01 -> FR-1, Q01 -> Q1。"""
    if "-" in raw:
        prefix, num = raw.rsplit("-", 1)
        return f"{prefix}-{int(num)}"
    m = re.match(r"([A-Z]+)(\d+)", raw)
    if m:
        return f"{m.group(1)}{int(m.group(2))}"
    return raw


def scan_docs(docs_dir: Path) -> dict:
    """扫描 docs/ 目录，提取所有 ID 并交叉验证。"""
    all_ids: dict[str, dict[str, set[str]]] = {}  # file -> {prefix -> ids}
    all_defs: set[str] = set()
    all_refs: set[str] = set()  # 标准化后的引用集合
    all_refs_raw: set[str] = set()  # 原始引用（用于报告）
    versions: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    for md in sorted(docs_dir.rglob("*.md")):
        text = md.read_text(encoding="utf-8", errors="replace")
        rel = str(md.relative_to(docs_dir))

        # 提取引用 ID（标准化）
        ids = extract_ids(text)
        all_ids[rel] = ids
        for prefix, id_set in ids.items():
            for id_val in id_set:
                norm = normalize_id(id_val)
                all_refs.add(norm)
                all_refs_raw.add(id_val)

        # 提取定义 ID（标准化）
        defs = extract_definitions(text)
        for d in defs:
            all_defs.add(normalize_id(d))

        # 提取版本号（只取标题行的版本声明，正文提及不算冲突）
        title_m = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
        doc_name = title_m.group(1).strip() if title_m else md.stem
        # 只从标题和明确的"版本:"行提取声明版本
        declared_versions = set()
        if title_m:
            for v in VERSION_PATTERN.findall(title_m.group(1)):
                declared_versions.add(f"V{v}")
        for line in text.splitlines()[:10]:  # 前 10 行通常是元数据区
            if re.match(r"^版本[::]", line.strip()) or re.match(r"^version[::]", line.strip(), re.IGNORECASE):
                for v in VERSION_PATTERN.findall(line):
                    declared_versions.add(f"V{v}")
        if declared_versions:
            versions[doc_name][rel] = declared_versions

    # 跨文档分析（孤儿只针对需求类 ID；TR/Q 为门禁/质量术语，不参与孤儿判定）
    def _prefix(nid: str) -> str:
        m = re.match(r"[A-Z]+", nid)
        return m.group(0) if m else ""
    orphan_refs = sorted(r for r in (all_refs - all_defs - EXEMPT_REFS) if _prefix(r) in REQUIREMENT_PREFIXES)
    unused_defs = sorted(all_defs - all_refs)
    version_conflicts = []
    for doc_name, files in versions.items():
        all_vers = set()
        for vers in files.values():
            all_vers |= vers
        if len(all_vers) > 1:
            version_conflicts.append({
                "document": doc_name,
                "versions": sorted(all_vers),
                "files": {k: sorted(v) for k, v in files.items()},
            })

    return {
        "docs_dir": str(docs_dir),
        "files_scanned": len(all_ids),
        "total_ids": len(all_refs),
        "total_defs": len(all_defs),
        "orphan_refs": orphan_refs,
        "unused_defs": unused_defs,
        "version_conflicts": version_conflicts,
        "consistency": len(orphan_refs) == 0 and len(version_conflicts) == 0,
    }


def check_id(id_val: str, docs_dir: Path) -> dict:
    """检查单个 ID 的定义与引用分布。"""
    id_norm = normalize_id(id_val)
    # 生成搜索模式：匹配 FR-1, FR-01, FR-001 等各种零填充形式
    parts = id_norm.rsplit("-", 1) if "-" in id_norm else [id_norm, None]
    if parts[1] is not None:
        prefix, num = parts
        n = int(num)
        # 匹配 FR-1, FR-01, FR-001 等零填充形式（不用 \b，中文相邻漏检）
        search_pat = re.compile(rf"(?<![A-Za-z0-9-]){prefix}-0*{n}(?![0-9])")
    else:
        m = re.match(r"([A-Z]+)(\d+)", id_norm)
        if m:
            search_pat = re.compile(rf"\b{m.group(1)}{int(m.group(2))}\b")
        else:
            search_pat = re.compile(re.escape(id_norm))
    definitions = []
    references = []
    for md in sorted(docs_dir.rglob("*.md")):
        text = md.read_text(encoding="utf-8", errors="replace")
        rel = str(md.relative_to(docs_dir))
        if id_norm in extract_definitions(text):
            definitions.append(rel)
        if search_pat.search(text):
            references.append(rel)
    return {
        "id": id_norm,
        "defined_in": definitions,
        "referenced_in": references,
        "has_definition": len(definitions) > 0,
        "consistency": len(definitions) > 0 or len(references) == 0,
    }


def format_text_report(result: dict) -> str:
    lines = [
        f"=== 跨文档一致性报告 ===",
        f"扫描目录: {result['docs_dir']}",
        f"文件数: {result['files_scanned']}  ID 总数: {result['total_ids']}  定义数: {result['total_defs']}",
        f"一致性: {'✓ 通过' if result['consistency'] else '✗ 不一致'}",
        "",
    ]
    if result["orphan_refs"]:
        lines.append(f"孤儿引用（{len(result['orphan_refs'])} 个，被引用但无定义）:")
        for i in result["orphan_refs"][:20]:
            lines.append(f"  - {i}")
        if len(result["orphan_refs"]) > 20:
            lines.append(f"  ... 共 {len(result['orphan_refs'])} 个")
    else:
        lines.append("孤儿引用: 无 ✓")
    lines.append("")
    if result["version_conflicts"]:
        lines.append(f"版本冲突（{len(result['version_conflicts'])} 个文档）:")
        for vc in result["version_conflicts"]:
            lines.append(f"  {vc['document']}: {vc['versions']}")
    else:
        lines.append("版本冲突: 无 ✓")
    lines.append("")
    if result["unused_defs"]:
        lines.append(f"未引用定义（{len(result['unused_defs'])} 个，仅供参考）:")
        for i in result["unused_defs"][:10]:
            lines.append(f"  - {i}")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="跨文档一致性校验工具（只读）")
    sub = parser.add_subparsers(dest="cmd")

    p_scan = sub.add_parser("scan", help="扫描 docs/ 目录并输出一致性报告")
    p_scan.add_argument("docs_dir", nargs="?", default=DEFAULT_DOCS_DIR)
    p_scan.add_argument("--report", choices=["text", "json"], default="text")

    p_check = sub.add_parser("check", help="检查单个 ID 的定义与引用")
    p_check.add_argument("id", help="如 FR-001, CC-01, TR4")
    p_check.add_argument("docs_dir", nargs="?", default=DEFAULT_DOCS_DIR)

    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    if args.cmd == "scan":
        docs_dir = Path(args.docs_dir)
        if not docs_dir.exists():
            print(f"FAIL: 目录不存在: {docs_dir}", file=sys.stderr)
            return 2
        result = scan_docs(docs_dir)
        if args.report == "json":
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(format_text_report(result))
        return 0 if result["consistency"] else 1

    if args.cmd == "check":
        docs_dir = Path(args.docs_dir)
        if not docs_dir.exists():
            print(f"FAIL: 目录不存在: {docs_dir}", file=sys.stderr)
            return 2
        result = check_id(args.id, docs_dir)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0  # 查询命令：只要执行成功就返回 0

    parser.print_help()
    return 2


def _self_test() -> int:
    passed = 0
    failed = 0

    def check(name, ok):
        nonlocal passed, failed
        if ok:
            passed += 1
            print(f"[PASS] {name}")
        else:
            failed += 1
            print(f"[FAIL] {name}")

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        docs = Path(tmp)

        # 创建测试文档
        (docs / "requirements.md").write_text(
            "# 需求规格\n\n## FR-001 用户登录\n用户可通过手机号登录。\n\n"
            "## FR-002 数据导出\n用户可导出 CSV。\n\n"
            "## NFR-001 性能\n响应时间 < 2s。\n",
            encoding="utf-8",
        )
        (docs / "design.md").write_text(
            "# 技术方案 V1.3\n\n"
            "## FR-001 实现\n登录模块实现。\n\n"
            "引用 FR-002 做导出。引用 FR-999 做测试。\n"
            "风险 RISK-001 数据安全。\n",
            encoding="utf-8",
        )
        (docs / "test.md").write_text(
            "# 测试计划\n\n"
            "覆盖 FR-001, FR-002, NFR-001。\n"
            "TR4 评审节点。\n",
            encoding="utf-8",
        )

        # 测试 1: 扫描
        result = scan_docs(docs)
        check("扫描执行", result["files_scanned"] == 3)
        check("提取 ID", result["total_ids"] >= 4)

        # 测试 2: 孤儿引用（FR-999 被引用但无定义）
        check("孤儿引用检出", "FR-999" in result["orphan_refs"])

        # 测试 3: 一致性 = False（因有孤儿）
        check("一致性判断", result["consistency"] is False)

        # 测试 4: 版本冲突（V1.3 只出现一次，应无冲突）
        check("版本无冲突", len(result["version_conflicts"]) == 0)

        # 测试 5: 单 ID 检查
        r2 = check_id("FR-001", docs)
        check("FR-001 有定义", r2["has_definition"] is True)
        check("FR-001 有引用", len(r2["referenced_in"]) >= 2)

        # 测试 6: 不存在的 ID
        r3 = check_id("FR-999", docs)
        check("FR-999 无定义", r3["has_definition"] is False)

        # 测试 7: 版本冲突检测（同一文档标题声明 V1.3，元数据行声明 V1.2）
        (docs / "design.md").write_text(
            "# 技术方案 V1.3\n\n版本: V1.2\n\n内容……\n",
            encoding="utf-8",
        )
        result2 = scan_docs(docs)
        check("版本冲突检出", len(result2["version_conflicts"]) >= 1)

    # 测试 8: ID 标准化
    check("ID 标准化 FR-01", normalize_id("FR-01") == "FR-1")
    check("ID 标准化 TR4", normalize_id("TR4") == "TR4")

    # 测试 9: 空目录
    with tempfile.TemporaryDirectory() as tmp2:
        result3 = scan_docs(Path(tmp2))
        check("空目录无问题", result3["consistency"] is True)

    # 测试 10: 文本报告生成
    with tempfile.TemporaryDirectory() as tmp3:
        docs3 = Path(tmp3)
        (docs3 / "a.md").write_text("# A\n\nFR-001 定义\n", encoding="utf-8")
        r = scan_docs(docs3)
        txt = format_text_report(r)
        check("报告生成", "跨文档一致性报告" in txt)

    print(f"\n[汇总] {passed}/{passed + failed} 通过")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
