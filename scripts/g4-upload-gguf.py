import paramiko
import os
from pathlib import Path
import time
import sys

HOST = "192.168.31.166"
USER = "root"
PASS = os.environ.get("SSH_PASSWORD")
if not PASS:
    raise SystemExit("[FATAL] 环境变量 SSH_PASSWORD 未设置（口令仅经环境变量注入，严禁硬编码/入库）")

LOCAL_GGUF = Path(r"c:\Users\Robin\Desktop\方案\security-ai-gateway\.tools\models\Qwen3Guard-Gen-0.6B-GGUF\Qwen3Guard-Gen-0.6B.Q8_0.gguf")
REMOTE_GGUF = "/opt/og16-g4/gguf/Qwen3Guard-Gen-0.6B.Q8_0.gguf"


def main():
    file_size = os.path.getsize(LOCAL_GGUF)
    print(f"本地文件: {LOCAL_GGUF.name}")
    print(f"大小: {file_size / (1024*1024):.1f} MB")
    print(f"目标: {REMOTE_GGUF}")
    print()

    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=10)

    # 先检查是否已经上传过
    rc, stdout, stderr = c.exec_command(f"ls -lh {REMOTE_GGUF} 2>&1")
    out = stdout.read().decode()
    if "Q8_0" in out and "767" in out:
        print("✅ 文件已存在，跳过上传")
        print(out.strip())
        c.close()
        return

    print("🚀 开始上传 (SFTP)...")
    sftp = c.open_sftp()

    start = time.time()
    last_report = start
    uploaded = 0

    def progress(transferred, total):
        nonlocal last_report, uploaded
        now = time.time()
        uploaded = transferred
        if now - last_report >= 5:  # 每 5 秒报告一次
            speed = transferred / (now - start) / (1024*1024)
            pct = transferred / total * 100
            eta = (total - transferred) / (transferred / (now - start)) if transferred > 0 else 0
            print(f"  进度: {pct:.1f}% ({transferred/(1024*1024):.0f}/{total/(1024*1024):.0f} MB) "
                  f"速度: {speed:.1f} MB/s 预计剩余: {eta/60:.1f} min")
            last_report = now

    sftp.put(str(LOCAL_GGUF), REMOTE_GGUF, callback=progress)
    sftp.close()

    elapsed = time.time() - start
    print(f"\n✅ 上传完成！耗时: {elapsed/60:.1f} 分钟，平均速度: {file_size/elapsed/(1024*1024):.1f} MB/s")

    # 校验
    rc, stdout, _ = c.exec_command(f"ls -lh {REMOTE_GGUF} && md5sum {REMOTE_GGUF}")
    print("\n远端文件信息:")
    print(stdout.read().decode().strip())

    c.close()


if __name__ == "__main__":
    main()
