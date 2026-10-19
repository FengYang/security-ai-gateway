import os
import paramiko
import time

HOST = "192.168.31.166"
USER = "root"
PASS = os.environ.get("SSH_PASSWORD")
if not PASS:
    raise SystemExit("[FATAL] 环境变量 SSH_PASSWORD 未设置（口令仅经环境变量注入，严禁硬编码/入库）")


def run(c, cmd, timeout=30):
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    return rc, out, err


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)

    # 1. 启动 llama-server（后台）
    print("=== 1. 启动 llama-server ===")
    # 先杀掉可能存在的旧进程
    run(c, "pkill -f 'llama-server' 2>/dev/null; sleep 1")

    llama_cmd = (
        "nohup /opt/og16-g4/llama/llama-server "
        "-m /opt/og16-g4/gguf/Qwen3Guard-Gen-0.6B.Q8_0.gguf "
        "--port 19110 --host 0.0.0.0 "
        "-np 2 -c 2048 "
        "> /opt/og16-g4/llama-server.log 2>&1 &"
    )
    run(c, llama_cmd)
    time.sleep(2)

    # 检查进程
    rc, out, _ = run(c, "ps aux | grep 'llama-server' | grep -v grep | head -3")
    print("llama-server 进程:", out.strip() or "(未找到)")

    # 等待健康检查（加载模型可能需要 10-30 秒）
    print("\n=== 2. 等待 llama-server 健康（加载模型中，约 30s）===")
    for i in range(30):
        time.sleep(2)
        rc, out, _ = run(c, "curl -s http://127.0.0.1:19110/health 2>&1")
        if rc == 0 and "status" in out.lower():
            print(f"  ✅ llama-server 就绪（第 {i*2}s）: {out.strip()[:100]}")
            break
    else:
        print("  ⚠️ 30s 内未就绪，检查日志...")
        rc, out, _ = run(c, "tail -20 /opt/og16-g4/llama-server.log")
        print(out[-1000:])

    # 3. 启动侧车（后台）
    print("\n=== 3. 启动侧车 ===")
    run(c, "pkill -f 'qwen3guard-l2-sidecar' 2>/dev/null; sleep 1")

    sidecar_cmd = (
        "nohup /opt/og16-g4/venv/bin/python "
        "/opt/og16-g4/sidecar/qwen3guard-l2-sidecar.py "
        "--port 19112 --llama-url http://127.0.0.1:19110 "
        "> /opt/og16-g4/sidecar.log 2>&1 &"
    )
    run(c, sidecar_cmd)
    time.sleep(3)

    rc, out, _ = run(c, "ps aux | grep 'qwen3guard-l2' | grep -v grep | head -3")
    print("侧车进程:", out.strip() or "(未找到)")

    # 4. 侧车健康检查
    print("\n=== 4. 侧车健康检查 ===")
    for i in range(10):
        time.sleep(2)
        rc, out, _ = run(c, "curl -s http://127.0.0.1:19112/healthz 2>&1")
        if rc == 0 and "ok" in out.lower():
            print(f"  ✅ 侧车就绪（第 {i*2}s）: {out.strip()[:100]}")
            break
    else:
        print("  ⚠️ 侧车未就绪，检查日志...")
        rc, out, _ = run(c, "tail -20 /opt/og16-g4/sidecar.log")
        print(out[-1000:])

    # 5. 快速验证：发一个 safe 句子
    print("\n=== 5. 快速验证（safe 句子） ===")
    rc, out, _ = run(c, """
    curl -s -X POST http://127.0.0.1:19112/classify \\
      -H 'Content-Type: application/json' \\
      -d '{"text": "今天天气真好，适合出去玩。"}' 2>&1 | head -c 500
    """)
    print(out.strip()[:500])

    c.close()
    print("\n✅ llama-server + 侧车启动完成")


if __name__ == "__main__":
    main()
