#!/usr/bin/env python3
"""明文凭据门禁（secrets-guard）：禁止把口令/密钥字面量写入仓库。

背景（2026-10-19，P2-1 T-4 集群窗口发现）：68 个已入库脚本硬编码远程口令
（`PASS = "<口令>"` 形态），违反「口令严禁写入仓库/文件，仅经 `SSH_PASSWORD`
环境变量注入」铁律。本门禁把该口径机械化，防再犯。

扫描范围：**本仓库 git 跟踪文件**（`git ls-files`），跳过二进制/超大文件与
`vendor/`、`node_modules/`、`.tools/`。

三类规则：
  ① cred-literal  凭据变量赋值为字符串字面量（pass/password/pwd/secret/token/
                   api_key/access_key/auth_token/private_key/client_secret；含
                   `VAR = "..."`、`"password": "..."`、`password: "..."` 形态）
  ② url-userinfo  URL userinfo 携带口令：`scheme://user:password@host`
  ③ env-secret    环境提供的**实际口令值**在任何跟踪文件中原样出现
                   （取 `SECRETS_GUARD_VALUES`（逗号分隔）与 `SSH_PASSWORD`；
                   未设置则本规则不生效）

判定与基线：
  - 命中「占位符」字面量（CHANGE_ME / xxx / *** / `<...>` / ${...} / %s …）不计。
  - 既有债务登记于 `scripts/secrets-baseline.txt`（`path<TAB>rule<TAB>sha256前12`）；
    基线内的命中计为 INFO（不失败），**同文件同规则的新值**（新哈希）仍失败。
  - 命中基线外任一 ⇒ 非 0 退出；日志只回显脱敏预览。

用法：
  python scripts/check-secrets.py                  # 全量扫描（含基线判定）
  python scripts/check-secrets.py --no-baseline    # 忽略基线（审计用，当前应有历史命中）
  python scripts/check-secrets.py --update-baseline # 依据当前命中重建基线（需人工复核后提交）
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

SELF = "scripts/check-secrets.py"
BASELINE_REL = "scripts/secrets-baseline.txt"

SKIP_DIRS = ("vendor/", "node_modules/", ".tools/", ".git/")
SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".pdf", ".wasm", ".gguf",
    ".zip", ".gz", ".tar", ".tgz", ".jar", ".bin", ".so", ".dll", ".exe", ".dylib",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".lock",
}
MAX_BYTES = 1_000_000

PLACEHOLDER = re.compile(
    r"""^(?:
        \$\{[^}]*\} | \$\([^)]*\) | \{\{[^}]*\}\} | <[^>]*> | %s | %
        \([\w]+\)s | -{2,} | \*{2,} | `{2,} | x{3,} | X{3,} | \.{3} |
        change[_-]?me | changeme | redacted | placeholder | dummy | example |
        your[_-]?\w* | my[_-]?\w* | foo | bar | test | todo | none | null | empty |
        \w*_?here | \w*_?value | env\W.* | process\.env\W.* | os\.environ.*
    )$""",
    re.IGNORECASE | re.VERBOSE,
)

CRED_NAMES = (
    r"pass(?:wd|word|phrase)?|pwd|secret|token|"
    r"api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret"
)

RULES = [
    (
        "cred-literal",
        re.compile(
            r"""(?ix)
            (?:
                \b(?:%s)\b \s* [:=] \s*          |
                ['"](?:%s)['"] \s* [:=] \s*
            )
            (?P<q>['"])(?P<val>(?:(?!(?P=q))[^\n]){3,128})(?P=q)
            """ % (CRED_NAMES, CRED_NAMES)
        ),
    ),
    (
        "url-userinfo",
        re.compile(
            r"""(?x)
            \b[a-zA-Z][a-zA-Z0-9+.\-]*:// [^/\s:@]+ : (?P<val>[^/\s:@'"]{3,128}) @
            """
        ),
    ),
]


def repo_root() -> Path:
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, check=True
    ).stdout.decode("utf-8", "surrogateescape").strip()
    return Path(out)


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True
    ).stdout
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]


def readable(root: Path, rel: str) -> str | None:
    norm = rel.replace("\\", "/")
    if norm in (SELF, BASELINE_REL):
        return None
    if any(f"/{d}" in f"/{norm}" for d in SKIP_DIRS):
        return None
    if os.path.splitext(norm)[1].lower() in SKIP_EXT:
        return None
    p = root / rel
    try:
        if p.stat().st_size > MAX_BYTES:
            return None
        raw = p.read_bytes()
    except OSError:
        return None
    if b"\0" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def masked(val: str) -> str:
    val = val.strip()
    if len(val) <= 2:
        return "*" * len(val)
    return val[0] + "*" * (len(val) - 2) + val[-1]


def h12(val: str) -> str:
    return hashlib.sha256(val.strip().encode("utf-8")).hexdigest()[:12]


def env_secrets() -> list[str]:
    vals: list[str] = []
    for var in ("SECRETS_GUARD_VALUES", "SSH_PASSWORD"):
        for v in os.environ.get(var, "").split(","):
            v = v.strip()
            if len(v) >= 6:
                vals.append(v)
    out: list[str] = []
    for v in vals:
        if v not in out:
            out.append(v)
    return out


def load_baseline(path: Path) -> set[tuple[str, str, str]]:
    if not path.is_file():
        return set()
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) == 3:
            out.add((parts[0].strip(), parts[1].strip(), parts[2].strip()))
    return out


def scan(root: Path, files: list[str], secrets: list[str]):
    """返回 findings: list[(path, line, rule, value)]"""
    findings = []
    for rel in files:
        text = readable(root, rel)
        if text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for name, rx in RULES:
                for m in rx.finditer(line):
                    val = m.group("val")
                    if PLACEHOLDER.match(val):
                        continue
                    findings.append((rel.replace("\\", "/"), lineno, name, val))
        if secrets:
            for v in secrets:
                if v in text:
                    findings.append((rel.replace("\\", "/"), 0, "env-secret", v))
    return findings


def main(argv: list[str]) -> int:
    use_baseline = "--no-baseline" not in argv
    update = "--update-baseline" in argv
    root = repo_root()
    baseline_path = root / BASELINE_REL

    files = tracked_files(root)
    secrets = env_secrets()
    findings = scan(root, files, secrets)

    if update:
        lines = [
            "# 明文凭据门禁基线（scripts/check-secrets.py）",
            "# 格式：<path>\\t<rule>\\t<sha256(值)前12>",
            "# 说明：既有债务登记；同文件同规则的**新值**（新哈希）仍会失败。",
            "# 新增条目须人工复核（确认非新增泄漏）后提交。",
        ]
        for path, _ln, rule, val in sorted(findings):
            lines.append(f"{path}\t{rule}\t{h12(val)}")
        baseline_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"[secrets-guard] 已写入基线：{BASELINE_REL}（{len(findings)} 条）")
        return 0

    baseline = load_baseline(baseline_path) if use_baseline else set()
    new, known = [], []
    for path, ln, rule, val in findings:
        if (path, rule, h12(val)) in baseline:
            known.append(path)
        else:
            new.append(f"{path}:{ln}: [{rule}] 明文凭据字面量（预览 {masked(val)}）")

    scope = f"{len(files)} 个跟踪文件"
    extra = (
        f"；规则③已启用（{len(secrets)} 个环境口令值）"
        if secrets
        else "；规则③未启用（未设 SSH_PASSWORD/SECRETS_GUARD_VALUES）"
    )

    if new:
        scope_txt = "检出**新增**明文凭据" if use_baseline else "检出明文凭据（--no-baseline）"
        print(f"FAIL: secrets-guard {scope_txt}（口令仅经环境变量注入，严禁入库）：")
        for f in new:
            print("  " + f)
        print(f"\n新增 {len(new)} 处（基线内 {len(known)} 处不阻塞）；修复后重试。")
        print(f"若确属既有债务：复核后执行 `python scripts/check-secrets.py --update-baseline`。")
        return 1

    if use_baseline:
        print(f"PASS: secrets-guard 通过（{scope}{extra}；基线内既有 {len(known)} 处）")
    else:
        print(f"PASS(--no-baseline): secrets-guard 通过（{scope}{extra}）")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
