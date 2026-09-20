import paramiko

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

    # 先看看那 20 字节是什么
    print("=== 下载的文件内容（20字节）===")
    rc, out, _ = run(c, "cat /opt/og16-g4/gguf/Qwen3Guard-Gen-0.6B.Q8_0.gguf | xxd | head -3")
    print(out)

    # 删掉坏文件
    run(c, "rm -f /opt/og16-g4/gguf/Qwen3Guard-Gen-0.6B.Q8_0.gguf")

    # 试试直接从 HuggingFace 原站下
    print("\n=== 测试 hf.co 连通性 ===")
    rc, out, _ = run(c, "curl -sI https://huggingface.co/Qwen/Qwen3Guard-Gen-0.6B-GGUF/resolve/main/Qwen3Guard-Gen-0.6B.Q8_0.gguf 2>&1 | head -15", timeout=30)
    print(out)

    # 再试 modelscope
    print("\n=== 测试 modelscope ===")
    rc, out, _ = run(c, "curl -sI 'https://www.modelscope.cn/models/qwen/Qwen3Guard-Gen-0.6B-GGUF/resolve/master/Qwen3Guard-Gen-0.6B.Q8_0.gguf' 2>&1 | head -15", timeout=30)
    print(out)

    c.close()


if __name__ == "__main__":
    main()
