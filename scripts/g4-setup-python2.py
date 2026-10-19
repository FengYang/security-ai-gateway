import os
import paramiko

HOST = "192.168.31.166"
USER = "root"
PASS = os.environ.get("SSH_PASSWORD")
if not PASS:
    raise SystemExit("[FATAL] 环境变量 SSH_PASSWORD 未设置（口令仅经环境变量注入，严禁硬编码/入库）")


def run(c, cmd, timeout=120):
    print(f"$ {cmd[:100]}...")
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    if out.strip():
        print(out.rstrip()[-800:])
    if err.strip() and "WARNING" not in err and "warning" not in err:
        print("STDERR:", err.rstrip()[-300:])
    print(f"  → exit {rc}\n")
    return rc, out, err


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)

    # 1. 装 python3-venv 和 pip
    print("=== 1. 安装 python3-venv + pip ===")
    run(c, "apt-get update -qq 2>&1 | tail -3", timeout=120)
    run(c, "apt-get install -y -qq python3-venv python3-pip 2>&1 | tail -5", timeout=180)

    # 2. 创建 venv 并安装依赖
    print("=== 2. 创建 venv + 安装 httpx + transformers ===")
    run(c, "rm -rf /opt/og16-g4/venv && python3 -m venv /opt/og16-g4/venv", timeout=60)
    run(c, "/opt/og16-g4/venv/bin/pip install --no-cache-dir httpx 'transformers>=4.50' 2>&1 | tail -15", timeout=300)

    # 3. 验证
    print("=== 3. 验证 ===")
    run(c, "/opt/og16-g4/venv/bin/python -c 'import httpx; import transformers; print(\"httpx:\", httpx.__version__); print(\"transformers:\", transformers.__version__)'")

    # 4. 确认 GGUF
    print("=== 4. GGUF 文件确认 ===")
    run(c, "ls -lh /opt/og16-g4/gguf/")

    c.close()


if __name__ == "__main__":
    main()
