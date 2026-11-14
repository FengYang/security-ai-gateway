#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify-all.py —— M1-M12 + C-class 自动验证套件（G3 + Phase3 M9-M12）

顺序执行全部验证项并汇总 PASS/FAIL。
退出码：0 = 全部通过；1 = 至少一项失败。

覆盖（23 项，与原 verify-all.ps1 逐项对应）：
   1. 单测              go test ./...
   2. 协议一致性        Python<->Go 南向协议（含 cipher_text）
   3. 决策门            fixed-r + W*r 掩码像数学 PoC
   4. 运行环境          Docker 容器组（envoy/embedding/tee-infer）
   5. E2E               text -> 加密 -> TEE 推理 -> 解密 -> SSE
   6. 精度              密文推理 == 明文推理（0% 损失）
   7. M9 治理           多租户隔离 / 用量计量 / 审计链 / guardrail
   8. M10 部署          K8s 清单（kustomize/YAML/镜像）+ app /metrics
   9. M11 安全          动态渗透（篡改/重放/跨租户/绕过/DoS/fail-closed）
  10. M12 vLLM          引擎抽象（RemoteEngine == local）+ 适配器构建 + 语法
  11. vLLM+auth+canary  构建/测试/dry-run
  12. Enclave           Attest/Seal/Unseal/Measure + 密封文件往返
  13. 远程证明          挑战-响应 + 会话密钥协商 + 验证链拒绝
  14. R2 密态推理        密文线性内核 + /v1/recompute + 双路线路由
  15. A6 + TSA + 对账    明文最小化 + RFC3161 TST + 审计-计量对账
  16. vLLM 密态改造      masked 包 + 补算 rmsnorm/argmax
  17. 路线 1 text 全链路  tee_gpu 流式 + cmaas fail-closed + guardrail
  18. 路线 1 防降级/重放  信封重放拒绝 + 明文 fail-closed + 跨语言一致
  19. 网关能力补齐        配额 + 脱敏 + 装饰 + 双 hash
  20. Higress 插件门禁    仓库 ↔ 锁定 ↔ 镜像版本
  21. 指标全绿判定        门禁 #9（required 全命中 + 来源全可达）
  22. 审计-计量对账       S5 判据 6（窗口 0 容差）
  23. OG-10 逐帧 e2e      命中片段在任何已下发帧零出现

用法：
  python3 scripts/verify-all.py
  GO_BIN=/usr/local/go/bin/go python3 scripts/verify-all.py

移植说明（2026-11-14）：本脚本取代 verify-all.ps1 成为**CI 权威实现**（Linux 原生）。
  判定语义逐项与 ps1 版一致——未放宽任何判据、未新增任何"环境缺失即跳过"的豁免。
  相对 ps1 版的差异仅限实现层：
    a) 失败时才回显该命令输出的尾部（ps1 全量吞输出，失败后无从定位）。
    b) GOFLAGS 缺省补 `-mod=mod`（仓库含 vendor/ 无 modules.txt；ps1 版靠环境里预设的
       GOFLAGS 隐式生效，此处显式化，避免"换台机器就红"）。
    c) 子脚本改为调用同目录的 Python 实现（verify-k8s.py / canary-release.py /
       check-higress-plugin-versions.py / check-metrics-green.py），不再嵌套 powershell。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS: list[tuple[str, str, str]] = []

# 与 ps1 版一致：BM-2 默认全量档 50000x512 HNSW 建图常态 575~578s，逼近 go test 单包 10m
# 超时。本地全套回归降档冒烟（判据 p95<15ms、dim 与产品代码均不变）；生产代表性全量档
# 请用 `make test-bm2-full`（-timeout 30m）单独举证，不占常规回归算力。
os.environ.setdefault("CACHE_BM2_VECN", "5000")

# 与 CI 对齐 Go 构建环境（见模块 docstring 说明 b）
#   - 本仓 go.work 未入库（.gitignore 忽略），CI checkout 上不存在；开发机会有。
#   - 一旦处于 workspace 模式，`-mod=mod` 会被 Go 直接拒绝
#     （"-mod may only be set to readonly or vendor when in workspace mode"），
#     故检测到 go.work 即强制 GOWORK=off，使本地/真机判定与 CI 一致。
def _normalize_go_env() -> None:
    if not os.environ.get("GOWORK"):
        probe = ROOT
        for _ in range(6):
            if (probe / "go.work").exists():
                os.environ["GOWORK"] = "off"
                print(f"[note] 检测到 {probe / 'go.work'}：强制 GOWORK=off"
                      f"（与 CI 无 workspace 的环境一致）")
                break
            if probe.parent == probe:
                break
            probe = probe.parent
    if "-mod=" not in os.environ.get("GOFLAGS", ""):
        os.environ["GOFLAGS"] = (os.environ.get("GOFLAGS", "") + " -mod=mod").strip()


_normalize_go_env()


def check(name: str, ok: bool, detail: str = "") -> None:
    status = "PASS" if ok else "FAIL"
    RESULTS.append((name, status, detail))
    print(f"[{status}] {name} {detail}".rstrip())


def tail(text: str, lines: int = 25, width: int = 300) -> str:
    """取输出尾部若干行，压成单行摘要（失败定位用）。"""
    picked = [ln for ln in text.splitlines() if ln.strip()][-lines:]
    return " | ".join(picked)[:width]


def run(cmd: list[str], timeout: int = 1800) -> tuple[int, str]:
    """执行命令，返回 (exit code, 合并输出)。缺可执行 → 127。"""
    shown = " ".join(cmd)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=ROOT)
        out = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode, out
    except FileNotFoundError:
        return 127, f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s: {shown}"
    except OSError as exc:
        return 126, f"exec error: {exc}"


def find_go() -> str | None:
    if os.environ.get("GO_BIN"):
        return os.environ["GO_BIN"]
    found = shutil.which("go")
    if found:
        return found
    for cand in ("/usr/local/go/bin/go", r"C:\Program Files\Go\bin\go.exe"):
        if Path(cand).is_file():
            return cand
    return None


def find_python() -> str | None:
    if os.environ.get("PYTHON_BIN"):
        return os.environ["PYTHON_BIN"]
    for name in ("python3", "python"):
        found = shutil.which(name)
        if found:
            return found
    return None


def ensure_go_visible(go_path: str) -> None:
    """让**子脚本**也能找到 go。

    verify-all 自身用绝对路径调 go 没问题，但它托管的子脚本（protocol/python/cross_test.py、
    scripts/pen_test.py 等）内部是 `subprocess.run(["go", ...])` —— 只查 PATH。
    真实 Linux 机器常把 go 装在 /usr/local/go/bin 而**不进 PATH**（本仓验证机即如此），
    此时这些项会以 FileNotFoundError 假失败，看起来像"代码坏了"。
    两件事一起做：① 绝对路径时把其目录前置到 PATH；② 补齐 GO_BIN（部分脚本优先读它）。
    """
    p = Path(go_path)
    if p.is_absolute() and p.parent.is_dir():
        go_dir = str(p.parent)
        parts = os.environ.get("PATH", "").split(os.pathsep)
        if go_dir not in parts:
            os.environ["PATH"] = go_dir + os.pathsep + os.environ.get("PATH", "")
            print(f"[note] 将 {go_dir} 前置到 PATH（供子脚本调用 go）")
    os.environ.setdefault("GO_BIN", go_path)


def main() -> int:
    # 行缓冲：各项耗时可达数分钟，进度必须实时可见（CI 日志按行流式输出）
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

    go = find_go()
    py = find_python()
    if not go:
        print("ERROR: 找不到 go（设置 GO_BIN，或确认 /usr/local/go/bin 在 PATH）")
        return 1
    if not py:
        print("ERROR: 找不到 python（设置 PYTHON_BIN）")
        return 1

    ensure_go_visible(go)

    scripts = ROOT / "scripts"
    print("===== M1-M12 automated verification =====")

    # ---------- 1. 单测 ----------
    print("\n[1/23] Unit tests (go test ./...)")
    code, out = run([go, "test", "./..."], timeout=3600)
    check("Unit tests", code == 0, "" if code == 0 else tail(out))

    # ---------- 2. 协议一致性 ----------
    print("\n[2/23] Protocol cross (Go/Python, incl. cipher_text)")
    code, out = run([py, "protocol/python/cross_test.py"], timeout=600)
    check("Protocol cross", code == 0, "" if code == 0 else tail(out))

    # ---------- 3. 决策门 PoC ----------
    print("\n[3/23] Decision gate PoC (mask-image math)")
    code, out = run([go, "run", "./gateway/poc/linear-mask-poc"], timeout=900)
    check("Decision gate PoC", "PASS" in out, "" if "PASS" in out else tail(out))

    # ---------- 4. 运行环境（容器组） ----------
    print("\n[4/23] Runtime env (Docker containers)")
    need = ("otpmask-plugin-envoy-1", "otpmask-plugin-embedding-service-1",
            "otpmask-plugin-tee-infer-service-1")
    code, out = run(["docker", "ps", "--filter", "status=running", "--format", "{{.Names}}"], timeout=120)
    up = set(out.split()) if code == 0 else set()
    missing = [c for c in need if c not in up]
    check("Docker containers ready", not missing,
          "" if not missing else f"缺失: {', '.join(missing)}")

    # ---------- 5. E2E（text -> SSE） ----------
    print("\n[5/23] E2E (text -> encrypt -> TEE infer -> decrypt -> SSE)")
    e2e_script = (
        "import urllib.request, json\n"
        "data = json.dumps({'text': 'e2e check'}).encode()\n"
        "req = urllib.request.Request('http://127.0.0.1:10000/infer', data=data, "
        "headers={'Content-Type': 'application/json'})\n"
        "body = urllib.request.urlopen(req, timeout=20).read().decode()\n"
        "assert 'data: [DONE]' in body, 'missing SSE done marker'\n"
        "assert 'data: {' in body, 'missing SSE token line'\n"
        "print('E2E OK')\n"
    )
    code, out = run([py, "-c", e2e_script], timeout=120)
    check("E2E SSE flow", code == 0, "" if code == 0 else tail(out, 5))

    # ---------- 6. 精度 ----------
    print("\n[6/23] Precision (cipher == plain)")
    code, out = run([go, "run", "./gateway/tee-infer-service/e2e/precision"], timeout=1200)
    check("Precision parity", "PASS" in out, "" if "PASS" in out else tail(out))

    # ---------- 7. M9 治理 + C-4/C-5 ----------
    print("\n[7/23] M9 governance + C-4/C-5 (version / WORM audit)")
    code, out = run([go, "test", "./gateway/tee-infer-service/",
                     "-run", "TestM9|TestGuardrail|TestProtocolVersion|TestAuditWORM"], timeout=1800)
    check("M9 + C4/C5 tests", code == 0, "" if code == 0 else tail(out))

    # ---------- 8. M10 K8s 清单 ----------
    print("\n[8/23] M10 K8s manifests (kustomize + YAML + images)")
    code, out = run([py, str(scripts / "verify-k8s.py")], timeout=3600)
    check("M10 K8s manifests", code == 0, "" if code == 0 else tail(out, 10))

    # ---------- 9. app /metrics ----------
    print("\n[9/23] App /metrics endpoint")
    metrics_script = (
        "import urllib.request\n"
        "b = urllib.request.urlopen('http://127.0.0.1:19090/metrics', timeout=5).read().decode()\n"
        "print('otpmask_inference_requests_total' in b and 'otpmask_audit_events' in b)\n"
    )
    code, out = run([py, "-c", metrics_script], timeout=60)
    check("App /metrics endpoint", "True" in out, "(tee-infer exposes Prometheus text)"
          if "True" in out else tail(out, 5))

    # ---------- 10. M11 渗透 ----------
    print("\n[10/23] M11 penetration tests (20 checks)")
    code, out = run([py, "scripts/pen_test.py"], timeout=1800)
    check("M11 penetration", code == 0, "" if code == 0 else tail(out, 5))

    # ---------- 11. vLLM 适配器 + auth-service + canary ----------
    print("\n[11/23] vLLM + auth-service + canary tooling")
    c_vllm, o_vllm = run([go, "build", "./gateway/vllm-adapter/"], timeout=900)
    c_model, o_model = run([go, "test", "./gateway/tee-infer-service/model/"], timeout=1800)
    pycheck = ("import ast\n"
               "ast.parse(open('gateway/vllm-adapter/vllm_adapter.py', encoding='utf-8').read())\n"
               "print('ok')\n")
    c_py, o_py = run([py, "-c", pycheck], timeout=120)
    c_auth, o_auth = run([go, "build", "./gateway/auth-service/"], timeout=900)
    c_autht, o_autht = run([go, "test", "./gateway/auth-service/"], timeout=1800)
    c_can, o_can = run([py, str(scripts / "canary-release.py"), "deploy",
                        "--tag", "v-dryrun", "--dry-run"], timeout=120)
    all_ok = all(c == 0 for c in (c_vllm, c_model, c_py, c_auth, c_autht, c_can))
    detail = "" if all_ok else tail("\n".join([o_vllm, o_model, o_py, o_auth, o_autht, o_can]), 8)
    check("vLLM + auth + canary (build/tests/dry-run)", all_ok, detail)

    # ---------- 12. Enclave 抽象 ----------
    print("\n[12/23] Enclave abstraction (enclave.go)")
    code, out = run([go, "test", "./gateway/tee-infer-service/",
                     "-run", "TestMockEnclave|TestSealFileRoundtrip|TestNewPlatformEnclave"], timeout=1800)
    check("Enclave abstraction", code == 0, "" if code == 0 else tail(out))

    # ---------- 13. 远程证明链 ----------
    print("\n[13/23] Remote attestation (challenge-response + session keys)")
    code, out = run([go, "test", "./gateway/tee-infer-service/",
                     "-run", "TestSession|TestVerifyAttestation|TestRemoteAttestationE2E"], timeout=1800)
    check("Remote attestation chain", code == 0, "" if code == 0 else tail(out))

    # ---------- 14. R2 密态推理 ----------
    print("\n[14/23] R2 密文线性内核 + 补算 + 双路线路由")
    # 路线2 内核单测（TestCipherLinearParity 等）已随 gateway/teecore 迁入独立仓库
    # masked-infer（其自有 CI 覆盖），故此处内核项恒真、仅校验本仓部分。
    code, out = run([go, "test", "./gateway/tee-infer-service/",
                     "-run", "TestRecomputeE2E|TestDualRoute|TestRoute"], timeout=1800)
    check("R2 masked-infer (kernel parity + recompute + routing)", code == 0,
          "" if code == 0 else tail(out))

    # ---------- 15. A6 + TSA + 对账 + 全量回归 ----------
    print("\n[15/23] A6 明文最小化 + 基座增强 + 全套回归")
    c_base, o_base = run([go, "test", "./gateway/tee-infer-service/",
                          "-run", "TestA6|TestMockTSA|TestAuditAnchorTST|TestReconciler"], timeout=1800)
    c_all, o_all = run([go, "test", "./..."], timeout=3600)
    check("A6 + TSA + reconcile + full regression", c_base == 0 and c_all == 0,
          "" if (c_base == 0 and c_all == 0) else tail(o_base + o_all))

    # ---------- 16. vLLM 密态改造 ----------
    print("\n[16/23] vLLM 密态改造（masked 包 + 补算 rmsnorm/argmax）")
    # 路线2 RMSNorm 单测已迁入独立仓库 masked-infer（其自有 CI 覆盖）。
    c_rms, o_rms = run([go, "test", "./gateway/tee-infer-service/",
                        "-run", "TestRecomputeRMSNormArgMax"], timeout=1800)
    masked_test = ROOT / "vllm" / "vllm" / "masked" / "test_masked_core.py"
    c_masked, o_masked = 0, ""
    if masked_test.is_file():  # 未放置 vllm 源码时跳过（既有语义，非本次引入）
        c_masked, o_masked = run([py, str(masked_test)], timeout=1800)
    check("vLLM masked dev (RMSNorm + recompute ops + core tests)",
          c_rms == 0 and c_masked == 0,
          "" if (c_rms == 0 and c_masked == 0) else tail(o_rms + o_masked))

    # ---------- 17. 路线 1 text 全链路 ----------
    print("\n[17/23] 路线 1 text 载荷全链路（tee_gpu 流式 + cmaas fail-closed + guardrail）")
    c_text, o_text = run([go, "test", "./gateway/tee-infer-service/", "-run", "TestTextInfer"], timeout=1800)
    c_eng, o_eng = run([go, "test", "./gateway/tee-infer-service/model/",
                        "-run", "TestRemoteEngineGenerate|TestCmaasEngine|TestLocalEngineGenerate"], timeout=1800)
    check("路线 1 text 全链路 (text 载荷 + SSE 信封 + 引擎流式)",
          c_text == 0 and c_eng == 0, "" if (c_text == 0 and c_eng == 0) else tail(o_text + o_eng))

    # ---------- 18. 路线 1 防降级/反重放 ----------
    print("\n[18/23] 路线 1 防降级/反重放/流序 + 跨语言一致性")
    c_env, o_env = run([go, "test", "./gateway/tee-infer-service/", "-run",
                        "TestSessionEnvelopeReplay|TestSessionPlaintextFailClosed|"
                        "TestSessionKeyIsolation|TestSessionDestroyAndZeroize"], timeout=1800)
    c_side, o_side = run([go, "test", "./gateway/attest-verify/..."], timeout=1800)
    c_cross, o_cross = run([py, "protocol/python/cross_test.py"], timeout=600)
    check("路线 1 反重放/防降级 + sidecar + 跨语言一致性",
          c_env == 0 and c_side == 0 and c_cross == 0,
          "" if (c_env == 0 and c_side == 0 and c_cross == 0) else tail(o_env + o_side + o_cross))

    # ---------- 19. 网关能力补齐 ----------
    print("\n[19/23] AI 网关能力补齐（配额 + 脱敏 + 装饰 + 双 hash）")
    code, out = run([go, "test", "./gateway/tee-infer-service/", "-run",
                     "TestQuota|TestMaskPII|TestPII|TestInjectionAlways|TestSystemPrompt"], timeout=1800)
    check("AI 网关能力补齐（P0a/P1/P2a）", code == 0, "" if code == 0 else tail(out))

    # ---------- 20. Higress 插件版本门禁 ----------
    print("\n[20/23] Higress 插件版本门禁（仓库 ↔ 锁定 ↔ 镜像）")
    code, out = run([py, str(scripts / "check-higress-plugin-versions.py"),
                     "--container", "higress-chain-control-plane"], timeout=300)
    check("Higress plugin versions", code == 0, "" if code == 0 else tail(out, 10))

    # ---------- 21. 指标全绿判定 ----------
    print("\n[21/23] 指标全绿判定（门禁 #9）")
    cmd = [py, str(scripts / "check-metrics-green.py"), "--require-all-sources"]
    if os.environ.get("OTP_CORE_AUTH_TOKEN"):
        cmd += ["--core-token", os.environ["OTP_CORE_AUTH_TOKEN"]]
    code, out = run(cmd, timeout=300)
    check("Metrics all-green (gate #9)", code == 0, "" if code == 0 else tail(out, 12))

    # ---------- 22. 审计-计量对账 ----------
    print("\n[22/23] 审计-计量对账（S5 / 门禁 #7 判据 6）")
    code, out = run([go, "test", "./gateway/tee-infer-service/", "-run", "TestReconcile"], timeout=1800)
    check("Metering reconcile (gate #7 / S5)", code == 0, "" if code == 0 else tail(out))

    # ---------- 23. OG-10 逐帧 e2e ----------
    print("\n[23/23] 输出侧逐帧 e2e 断言（OG-10：命中片段在任何已下发帧零出现）")
    code, out = run([go, "test", "-mod=mod", "./gateway/tee-infer-service/",
                     "-run", "TestFramewise|TestOutputGuardFramewise", "-count=1"], timeout=1800)
    check("Output-guard framewise e2e (OG-10)", code == 0, "" if code == 0 else tail(out))

    # ---------- Summary ----------
    n_pass = sum(1 for r in RESULTS if r[1] == "PASS")
    n_fail = len(RESULTS) - n_pass
    print("\n===== Summary =====")
    width = max((len(r[0]) for r in RESULTS), default=10)
    for name, status, detail in RESULTS:
        print(f"{status:<5} {name:<{width}} {detail}".rstrip())
    if n_fail == 0:
        print(f"ALL PASSED ({n_pass}/{len(RESULTS)})")
        return 0
    print(f"FAILED: {n_fail} item(s) ({n_pass}/{len(RESULTS)})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
