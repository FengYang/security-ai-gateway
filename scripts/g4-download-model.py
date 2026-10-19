import os
import paramiko
import time

HOST = "192.168.31.166"
USER = "root"
PASS = os.environ.get("SSH_PASSWORD")
if not PASS:
    raise SystemExit("[FATAL] 环境变量 SSH_PASSWORD 未设置（口令仅经环境变量注入，严禁硬编码/入库）")


def ssh_connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)
    return c


def run(c, cmd, timeout=120):
    print(f"$ {cmd}")
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if out.strip():
        print(out.rstrip()[-2000:])  # 最后2000字符
    if err.strip() and "Warning" not in err:
        print("STDERR:", err.rstrip()[-1000:])
    rc = stdout.channel.recv_exit_status()
    print(f"  → exit {rc}\n")
    return rc, out, err


def main():
    c = ssh_connect()

    # 先检查有没有下好的
    print("=== 检查现有文件 ===")
    rc, out, _ = run(c, "ls -lh /opt/og16-g4/llama/ 2>/dev/null; ls -lh /opt/og16-g4/gguf/ 2>/dev/null")

    # 下载 llama-server (llama.cpp release，Linux x64)
    # 用国内镜像快一点
    LLAMA_VERSION = "b4930"  # 最新 stable 版本
    LLAMA_URL = f"https://github.com/ggerganov/llama.cpp/releases/download/{LLAMA_VERSION}/llama-{LLAMA_VERSION}-bin-win-cuda-cu12.2.0-x64.zip"
    # Linux 的话用 ubuntu
    LLAMA_LINUX_URL = f"https://github.com/ggerganov/llama.cpp/releases/download/{LLAMA_VERSION}/llama-{LLAMA_VERSION}-bin-ubuntu-x64-cuda-12.2.zip"
    # 没有 GPU 的话用 CPU 版
    LLAMA_CPU_URL = f"https://github.com/ggerganov/llama.cpp/releases/download/{LLAMA_VERSION}/llama-{LLAMA_VERSION}-bin-ubuntu-x64.zip"

    # NUC7CJYH 没有 GPU（赛扬 J4005 是 UHD 600 核显，不支持 CUDA），用 CPU 版
    print("=== 下载 llama-server (CPU 版) ===")
    # 检查是否已下载
    rc, out, _ = run(c, "ls /opt/og16-g4/llama/llama-server 2>/dev/null")
    if rc != 0:
        # 用 hf-mirror 或者直接下
        run(c, f"cd /opt/og16-g4/llama && curl -L -o llama-cpu.zip '{LLAMA_CPU_URL}' 2>&1 | tail -5", timeout=300)
        run(c, "cd /opt/og16-g4/llama && unzip -o llama-cpu.zip 2>&1 | tail -5", timeout=60)
        run(c, "cd /opt/og16-g4/llama && ls -lh llama-server 2>&1")
    else:
        print("  已存在，跳过")

    # 下载 GGUF 模型
    print("=== 下载 Qwen3Guard-Gen-0.6B Q8_0 GGUF ===")
    # 供应链完整性：权重文件摘要固化（S0-⑧ / 缺口 D2 已闭合，2026-09-26 本机实测）
    GGUF_PATH = "/opt/og16-g4/gguf/Qwen3Guard-Gen-0.6B.Q8_0.gguf"
    GGUF_SHA256 = "127e8833aa16c6839613cd08df5409440302e8c61e90617914b3100f2141411a"
    # 来源留痕（S0-⑧ / 缺口 D1）：curl -D 落响应头，取 HF 分配的提交指纹
    # （x-repo-commit / x-linked-etag / etag）。D2 已钉住**字节**；D1 补的是**来源可追溯**——
    # resolve/main 可移动，故须记录"下载当时"的提交指纹并回填《GA-供应链与出境登记》D1 行。
    HDR_PATH = "/opt/og16-g4/gguf/.download.headers"
    rc, out, _ = run(c, "ls -lh /opt/og16-g4/gguf/*.gguf 2>/dev/null")
    if rc != 0 or "Q8_0" not in out:
        # 用 hf-mirror 加速
        GGUF_URL = "https://hf-mirror.com/Qwen/Qwen3Guard-Gen-0.6B-GGUF/resolve/main/Qwen3Guard-Gen-0.6B.Q8_0.gguf"
        run(c, f"cd /opt/og16-g4/gguf && curl -L -D {HDR_PATH} -o Qwen3Guard-Gen-0.6B.Q8_0.gguf '{GGUF_URL}' 2>&1 | tail -10", timeout=600)
        run(c, "ls -lh /opt/og16-g4/gguf/")
    else:
        print("  已存在，跳过（复用既有文件 ⇒ 无本次下载响应头；如需补录来源指纹见文末提示）")

    # 摘要校验（新增/已存在两路都校验）：不符即中止，避免供应链漂移被静默接受
    rc, out, _ = run(c, f"sha256sum {GGUF_PATH}")
    got = out.strip().split()[0] if out.strip() else ""
    if got != GGUF_SHA256:
        print(f"  ❌ sha256 不匹配：期望 {GGUF_SHA256}，实际 {got or '(空)'}")
        print("     供应链校验失败——请核对权重来源/替换审批，勿继续部署。")
        raise SystemExit(1)
    print(f"  ✅ sha256 校验通过：{got}")

    # 来源指纹（D1 关闭依据）：仅"本次下载"可得，命中即提示回填登记表。
    rc, out, _ = run(
        c,
        f"grep -iE '^(x-repo-commit|x-linked-etag|etag):' {HDR_PATH} 2>/dev/null | tail -5",
    )
    fingerprint = out.strip()
    if fingerprint:
        print("  📌 本次下载的来源指纹（请回填《GA-供应链与出境登记》缺口 D1，并把下载地址改为 resolve/<commit>）：")
        for line in fingerprint.splitlines():
            line = line.strip()
            if line:
                print(f"     {line}")
    else:
        print("  ⚠️ 未取得来源指纹（本次未下载，或镜像未返回 x-repo-commit/etag）：")
        print("     D1 仍待闭合——请在**可访问 HF** 的环境删除权重后重跑本脚本，或从 HF 页面手工取 revision。")

    c.close()


if __name__ == "__main__":
    main()
