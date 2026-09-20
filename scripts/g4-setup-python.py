import paramiko
import time

HOST = "192.168.31.166"
USER = "root"
PASS = "yf0537"


def run(c, cmd, timeout=120):
    print(f"$ {cmd[:100]}...")
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    if out.strip():
        print(out.rstrip()[-500:])
    if err.strip() and "WARNING" not in err and "warning" not in err:
        print("STDERR:", err.rstrip()[-300:])
    print(f"  → exit {rc}\n")
    return rc, out, err


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)

    # 1. 确保 pip 可用
    print("=== 1. 安装 pip ===")
    rc, out, _ = run(c, "python3 -m pip --version 2>&1")
    if rc != 0:
        run(c, "python3 -m ensurepip --upgrade 2>&1 | tail -5", timeout=60)
        run(c, "python3 -m pip install --upgrade pip 2>&1 | tail -3", timeout=60)

    # 2. 创建 venv 并安装依赖
    print("=== 2. 创建 venv 并安装 httpx + transformers ===")
    run(c, "python3 -m venv /opt/og16-g4/venv", timeout=60)
    # httpx 和 transformers（不带 torch，因为我们只用 tokenizer 和 chat template）
    run(c, "/opt/og16-g4/venv/bin/pip install --no-cache-dir httpx 'transformers>=4.50' 2>&1 | tail -10", timeout=300)

    # 3. 验证
    print("=== 3. 验证 ===")
    run(c, "/opt/og16-g4/venv/bin/python -c 'import httpx; import transformers; print(\"httpx:\", httpx.__version__); print(\"transformers:\", transformers.__version__)'")

    c.close()
    print("✅ Python 环境就绪")


if __name__ == "__main__":
    main()
