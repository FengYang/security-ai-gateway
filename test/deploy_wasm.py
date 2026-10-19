"""
WASM 插件部署脚本
通过 SSH 将源码上传到 Linux 节点，编译 wasm，部署到 wasm-files 服务。
依赖: pip install paramiko
用法:
  python deploy_wasm.py v6          # 编译新版本，版本标签 v6
  python deploy_wasm.py v6 --apply  # 编译并立即 patch WasmPlugin 生效
"""
import os
import paramiko
import argparse
import json

# ====== 配置 ======
NODE_IP = "192.168.31.168"
NODE_USER = "root"
NODE_PASS = os.environ.get("SSH_PASSWORD")
if not NODE_PASS:
    raise SystemExit("[FATAL] 环境变量 SSH_PASSWORD 未设置（口令仅经环境变量注入，严禁硬编码/入库）")
SRC_ROOT = r"c:\Users\Robin\Desktop\方案\security-ai-gateway"
SRC_RELATIVE = "gateway/wasm/otpmask-plugin"
BUILD_DIR = "/root/build/security-ai-gateway/gateway/wasm/otpmask-plugin"
PLUGINS_DIR = "/root/plugins"
# ==================


def upload_source(sftp, local_root, remote_root, files):
    """上传指定文件到节点"""
    for f in files:
        local = f"{local_root}/{f}"
        remote = f"{remote_root}/{f}"
        sftp.put(local, remote)
        print(f"  ↑ {f}")


def build_wasm(client, version_tag):
    """在节点上编译 wasm"""
    cmd = (
        f"export PATH=/usr/local/go/bin:$PATH && "
        f"cd {BUILD_DIR} && "
        f"GOOS=wasip1 GOARCH=wasm go build -o {PLUGINS_DIR}/otpmask-{version_tag}.wasm -buildmode=c-shared . 2>&1 && "
        f"ls -lh {PLUGINS_DIR}/otpmask-{version_tag}.wasm"
    )
    print("编译中...")
    stdin, stdout, stderr = client.exec_command(cmd, timeout=180)
    out = stdout.read().decode().strip()
    print(out)
    if "error" in out.lower() or "cannot" in out.lower():
        raise RuntimeError("编译失败")
    return f"otpmask-{version_tag}.wasm"


def apply_wasm(client, wasm_file, config):
    """patch WasmPlugin 使其加载新 wasm"""
    url = f"http://wasm-files.otpmask.svc.cluster.local/{wasm_file}?v=apply"
    patch = {
        "spec": {
            "defaultConfigDisable": True,
            "failStrategy": "FAIL_CLOSE",
            "matchRules": [{"ingress": ["infer"], "config": config}],
            "url": url
        }
    }
    patch_json = json.dumps(patch).replace("'", "'\\''")
    cmd = f"kubectl patch wasmplugin otpmask -n higress-system --type=merge -p '{patch_json}' 2>&1"
    result = _exec(client, cmd)
    print(f"  {result}")


def _exec(client, cmd, timeout=10):
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    return stdout.read().decode().strip()


def main():
    parser = argparse.ArgumentParser(description="部署 otpmask wasm 插件到 K3S 节点")
    parser.add_argument("version", help="版本标签，如 v6")
    parser.add_argument("--apply", action="store_true", help="编译后立即 patch 生效")
    args = parser.parse_args()

    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(NODE_IP, username=NODE_USER, password=NODE_PASS, timeout=10)
    sftp = c.open_sftp()

    print(f"上传源码到 {NODE_IP} ...")
    files = [
        "route.go",
        "routefetch.go",
        "main.go",
    ]
    upload_source(sftp, f"{SRC_ROOT}/{SRC_RELATIVE}", BUILD_DIR, files)
    sftp.close()

    wasm_file = build_wasm(c, args.version)
    print(f"✅ 编译完成: {wasm_file}")

    if args.apply:
        print("应用到 WasmPlugin ...")
        # 使用当前配置（这里只换 url 触发重新加载，config 沿用已有）
        # 简化：直接改 url 参数
        cmd = (
            f"kubectl patch wasmplugin otpmask -n higress-system --type=merge "
            f"-p '{{\"spec\":{{\"url\":\"http://wasm-files.otpmask.svc.cluster.local/{wasm_file}?v={args.version}\"}}}}' 2>&1"
        )
        result = _exec(c, cmd)
        print(f"  {result}")
        print("✅ 已触发 ECDS 更新（约 10s 生效）")

    c.close()


if __name__ == "__main__":
    main()
