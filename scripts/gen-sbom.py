#!/usr/bin/env python3
"""生成 CycloneDX 1.5 SBOM（方案 §6.3：主仓与新库须各带机器可读 SBOM）。

为什么自己写而不是引第三方工具（syft/cdxgen）：
  - 本仓 CI 的可信依赖面要尽量小（供应链门禁 trivy/govulncheck 已在跑），
    再拉一个生成器会新增一条需要持续审计的工具链；
  - 需要的输入 `go list -m -json all` 是 Go 工具链自带能力，解析成本很低。

NTIA 最小元素落点：
  - Supplier：第三方 OSS 无法确知 → "NOASSERTION"（不编造）；
  - Component name / version / unique id：模块路径 / 版本 / purl；
  - Dependency relationships：根组件 dependsOn 全部模块；
  - Author of SBOM data：OTP-Mask（工具条目）；
  - Timestamp：metadata.timestamp（可用 SBOM_TIMESTAMP 固定，便于 CI 做"是否过期"比对）。

确定性：除 timestamp 外输出稳定（模块按名称排序），故 CI 可用"重新生成 + diff"判定
依赖变更后 SBOM 是否忘记刷新。

用法：
    python scripts/gen-sbom.py [--out sbom.cyclonedx.json]
"""
import argparse
import json
import os
import subprocess
import sys

ROOT_COMPONENT = "security-ai-gateway"
BOM_FORMAT = "CycloneDX"
SPEC_VERSION = "1.5"


def go_module_list() -> list:
    """读取 `go list -m -json all` 的 JSON 流（-mod=mod：本仓有 vendor/ 但无 modules.txt）。"""
    env = dict(os.environ)
    env.setdefault("GOFLAGS", "-mod=mod")
    proc = subprocess.run(
        ["go", "list", "-m", "-json", "all"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit("gen-sbom: go list 失败（需在仓库根、且 go 工具链可用）")

    dec = json.JSONDecoder()
    out, idx, raw = [], 0, proc.stdout.strip()
    while idx < len(raw):
        obj, end = dec.raw_decode(raw, idx)
        out.append(obj)
        idx = end
        while idx < len(raw) and raw[idx] in " \n\t\r":
            idx += 1
    return out


def module_component(m: dict) -> dict:
    path = m["Path"]
    ver = m.get("Version", "")
    if m.get("Replace"):
        r = m["Replace"]
        path, ver = r.get("Path", path), r.get("Version", ver) or ver
    purl = f"pkg:golang/{path}"
    if ver:
        purl += f"@{ver}"
    comp = {
        "type": "library",
        "bom-ref": purl,
        "name": path,
        "version": ver,
        # 第三方 OSS 的供应商无法从模块元数据确知，按 NTIA 惯例标注 NOASSERTION，不编造。
        "supplier": {"name": "NOASSERTION"},
        "purl": purl,
    }
    # go 的 h1: 是 dirhash（对文件列表再哈希），**不是**模块文件的 SHA-256，
    # 直接当 file hash 填入会误导下游扫描器，故作为自定义属性保留原值。
    if m.get("Sum"):
        comp["properties"] = [{"name": "cdx:go:sum", "value": m["Sum"]}]
    return comp


def build_sbom(modules: list, timestamp: str) -> dict:
    comps, refs = [], []
    for m in modules:
        if m.get("Main"):
            continue  # 主模块作为 metadata.component，不重复列入依赖
        c = module_component(m)
        comps.append(c)
        refs.append(c["bom-ref"])
    comps.sort(key=lambda c: c["bom-ref"])
    refs.sort()

    root_ref = f"pkg:golang/{ROOT_COMPONENT}"
    sbom = {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"vendor": "OTP-Mask", "name": "gen-sbom.py", "version": "1"}],
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": ROOT_COMPONENT,
                "version": "0.0.0-dev",
            },
        },
        "components": comps,
        "dependencies": [{"ref": root_ref, "dependsOn": refs}],
    }
    return sbom


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="sbom.cyclonedx.json")
    args = ap.parse_args()

    ts = os.environ.get("SBOM_TIMESTAMP", "").strip()
    if not ts:
        # 缺省用固定值而非 now()：保证"同一份依赖 → 同一份文件"，否则每次生成都 diff 失败。
        # 需要真实时间时由发布流水线注入 SBOM_TIMESTAMP（RFC3339）。
        ts = "1970-01-01T00:00:00Z"

    sbom = build_sbom(go_module_list(), ts)
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(sbom, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"wrote {args.out}: {len(sbom['components'])} components")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
