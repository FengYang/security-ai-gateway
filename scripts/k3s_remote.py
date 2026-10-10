#!/usr/bin/env python3
"""
k3s_remote.py —— K3S 远程执行助手（本地 WSL → 远程 K3S 节点）。

用途：
  把“本助手 + 目标自携带脚本”上传到远程节点，在节点上以 --remote 模式执行目标脚本，
  回传输出。目标脚本无需自行处理 SSH / 口令。

凭据（严禁硬编码）：
  SSH_HOST      可选，默认 root@192.168.31.168
  SSH_PASSWORD  必填（远程登录口令）；未设置即明确报错退出。

命令行用法：
  python3 k3s_remote.py <目标脚本.py> [传给目标脚本的参数...]

代码用法：
  import k3s_remote
  k3s_remote.run_script("/abs/path/target.py", "--tenant", "t-smoke-001")

说明：仅依赖标准库；pty 为类 Unix 能力，请在 WSL/Linux 中运行“本地侧”。
被 import 时不执行任何 SSH 逻辑（因此本文件随目标脚本一起上传到节点也安全）。
"""
import base64
import os
import sys
import time

DEFAULT_HOST = "root@192.168.31.168"
REMOTE_WORKDIR = "/tmp/k3s-remote-run"


def _credentials():
    host = os.environ.get("SSH_HOST", DEFAULT_HOST)
    password = os.environ.get("SSH_PASSWORD")
    if not password:
        raise SystemExit(
            "k3s_remote: 未检测到环境变量 SSH_PASSWORD（远程登录口令必填，严禁硬编码）。\n"
            "请先设置，例如： export SSH_PASSWORD='********'"
        )
    return host, password


def _ssh(host, password, remote_cmd, timeout=600):
    """经 pty 运行单条 ssh 命令、自动应答口令，返回完整输出。"""
    import pty

    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(
            "ssh",
            [
                "ssh", "-q",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                host, remote_cmd,
            ],
        )
    output = b""
    start = time.time()
    pw_sent = False
    while time.time() - start < timeout:
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        output += data
        if not pw_sent and b"password:" in output.lower():
            os.write(fd, (password + "\n").encode())
            pw_sent = True
    os.waitpid(pid, 0)
    return output.decode("utf-8", errors="replace")


def run_script(local_py, *script_args, timeout=600):
    """上传助手与目标脚本到节点，远程以 --remote 模式执行目标脚本。"""
    host, password = _credentials()
    local_py = os.path.abspath(local_py)
    helper_path = os.path.abspath(__file__)

    with open(helper_path, "rb") as f:
        helper_b64 = base64.b64encode(f.read()).decode("ascii")
    with open(local_py, "rb") as f:
        target_b64 = base64.b64encode(f.read()).decode("ascii")

    helper_name = os.path.basename(helper_path)
    target_name = os.path.basename(local_py)
    quoted_args = " ".join("'" + a.replace("'", "'\\''") + "'" for a in script_args)

    remote_cmd = (
        f"mkdir -p '{REMOTE_WORKDIR}' && cd '{REMOTE_WORKDIR}' && "
        f"echo '{helper_b64}' | base64 -d > '{helper_name}' && "
        f"echo '{target_b64}' | base64 -d > '{target_name}' && "
        f"python3 '{target_name}' --remote {quoted_args}; "
        f"echo __K3S_REMOTE_EXIT__$?"
    )
    out = _ssh(host, password, remote_cmd, timeout=timeout)
    sys.stdout.write(out)
    return out


def main():
    if len(sys.argv) < 2:
        raise SystemExit("用法: python3 k3s_remote.py <目标脚本.py> [参数...]")
    run_script(sys.argv[1], *sys.argv[2:])


if __name__ == "__main__":
    main()
