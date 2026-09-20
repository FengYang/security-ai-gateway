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

    # 1. 修复 llama-server：用 build/bin 里的完整目录
    print("=== 1. 修复 llama-server 路径 ===")
    run(c, "ls /opt/og16-g4/llama/build/bin/*.so* 2>&1 | head -5")
    # 把整个 build/bin 复制到 llama 目录，设置 LD_LIBRARY_PATH
    run(c, "cp /opt/og16-g4/llama/build/bin/libllama.so /opt/og16-g4/llama/ 2>&1")
    run(c, "cp /opt/og16-g4/llama/build/bin/llama-server /opt/og16-g4/llama/ 2>&1")
    run(c, "ls -lh /opt/og16-g4/llama/libllama.so /opt/og16-g4/llama/llama-server")

    # 2. 测试能不能启动
    print("\n=== 2. 测试 llama-server 启动 ===")
    # 先杀掉残留
    run(c, "pkill -9 llama-server 2>/dev/null; sleep 1")
    # 用 LD_LIBRARY_PATH 启动
    llama_cmd = (
        "cd /opt/og16-g4/llama && "
        "LD_LIBRARY_PATH=/opt/og16-g4/llama "
        "nohup ./llama-server "
        "-m /opt/og16-g4/gguf/Qwen3Guard-Gen-0.6B.Q8_0.gguf "
        "--port 19110 --host 0.0.0.0 "
        "-np 2 -c 2048 "
        "> /opt/og16-g4/llama-server.log 2>&1 &"
    )
    run(c, llama_cmd)
    time.sleep(3)
    rc, out, _ = run(c, "ps aux | grep llama-server | grep -v grep | head -3")
    print("进程:", out.strip() or "(未找到)")

    # 等健康检查
    print("等待加载模型（可能 30-60s）...")
    for i in range(40):
        time.sleep(2)
        rc, out, _ = run(c, "curl -s http://127.0.0.1:19110/health 2>&1")
        if rc == 0 and "status" in out.lower():
            print(f"  ✅ llama-server 就绪（第 {(i+1)*2}s）: {out.strip()[:100]}")
            break
    else:
        print("  ❌ 未就绪，日志：")
        rc, out, _ = run(c, "tail -30 /opt/og16-g4/llama-server.log")
        print(out[-1500:])
        c.close()
        return

    # 3. 修复侧车：指定正确的模型目录（用于 tokenizer）
    print("\n=== 3. 侧车检查参数 ===")
    rc, out, _ = run(c, "grep -n 'model-dir\\|model_dir\\|tokenizer' /opt/og16-g4/sidecar/qwen3guard-l2-sidecar.py | head -20")
    print(out)

    # 侧车用 transformers 的 tokenizer，需要模型文件。但 GGUF 不能直接被 transformers 当模型目录用
    # 实际上，侧车只需要 tokenizer 和 chat template，不需要完整模型
    # 我们需要从 HuggingFace 下载 tokenizer 文件，或者用 llama-server 自己的 tokenizer
    # 更简单的方法：下载一个小的 tokenizer 到节点上
    print("\n=== 4. 下载 tokenizer 文件 ===")
    # Qwen3 系列的 tokenizer 可以用 Qwen/Qwen3-0.6B 的（同架构）
    run(c, "mkdir -p /opt/og16-g4/tokenizer")
    rc, out, _ = run(c, """
    cd /opt/og16-g4/tokenizer &&
    /opt/og16-g4/venv/bin/python -c "
from transformers import AutoTokenizer
tok = AutoTokenizer.from_pretrained('Qwen/Qwen3-0.6B', trust_remote_code=True)
tok.save_pretrained('/opt/og16-g4/tokenizer')
print('Tokenizer saved:', type(tok).__name__)
" 2>&1 | tail -10
    """, timeout=120)
    print(out)

    rc, out, _ = run(c, "ls -lh /opt/og16-g4/tokenizer/ | head -10")
    print(out)

    c.close()


if __name__ == "__main__":
    main()
