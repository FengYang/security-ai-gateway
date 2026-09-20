import paramiko
import time

HOST = "192.168.31.166"
USER = "root"
PASS = "yf0537"


def run(c, cmd, timeout=60):
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    return rc, out, err


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)

    # 先看 CPU 支持的指令集
    print("=== CPU 指令集 ===")
    rc, out, _ = run(c, "grep -m1 'flags' /proc/cpuinfo")
    flags = out.strip()
    print(flags[:200])
    has_avx = "avx " in flags or "avx2" in flags
    print(f"AVX2: {'avx2' in flags}, AVX: {'avx ' in flags or 'avx2' in flags}, SSE4.2: {'sse4_2' in flags}")

    # llama.cpp b4930 太新了，用一个更老的版本（b3xxx 应该支持旧 CPU）
    # 或者试试 b4380（一个较稳定的版本）
    # 实际上 llama.cpp 的 pre-built binary 默认会带 AVX2，旧 CPU 需要自己编译
    #
    # 更简单的方案：用 ollama 二进制？不对，ollama 也有同样问题
    # 最佳方案：从 llama.cpp release 下载 "noavx" 或 "avxonly" 构建
    # 但官方 release 只有一个 ubuntu-x64 版本，默认是 AVX2
    #
    # 替代方案：用 Python llama-cpp-python
    print("\n=== 方案：pip 安装 llama-cpp-python（编译时自动适配 CPU） ===")
    # 先装编译依赖
    run(c, "apt-get install -y -qq build-essential cmake pkg-config 2>&1 | tail -3", timeout=180)

    # 用 CMAKE_ARGS 强制 SSE4.2 only（避免 AVX）
    print("安装 llama-cpp-python...")
    rc, out, _ = run(c, """
    CMAKE_ARGS="-DLLAMA_AVX=OFF -DLLAMA_AVX2=OFF -DLLAMA_AVX512=OFF -DLLAMA_F16C=OFF -DLLAMA_FMA=OFF -DLLAMA_BUILD_SERVER=ON" \
    /opt/og16-g4/venv/bin/pip install --no-cache-dir 'llama-cpp-python[server]' 2>&1 | tail -20
    """, timeout=600)
    print(out[-1500:])

    # 验证
    print("\n=== 验证 ===")
    rc, out, _ = run(c, "/opt/og16-g4/venv/bin/python -c 'import llama_cpp; print(\"llama-cpp-python ok\")' 2>&1")
    print(out)
    rc, out, _ = run(c, "ls /opt/og16-g4/venv/bin/llama-server 2>&1 || find /opt/og16-g4/venv -name 'llama-server' -type f 2>&1 | head -3")
    print(out)

    c.close()


if __name__ == "__main__":
    main()
