#!/usr/bin/env bash
# check-tdx-vm.sh - 在阿里云 TDX 机密 VM（guest 内）检测 TDX 环境就绪度
#
# 背景：tee-infer 出"真 TDX Quote"需 guest 内具备
#   1) CPU 暴露 tdx_guest 标志（TD 实例创建生效）
#   2) /dev/tdx_guest 驱动（内核 TDX guest 支持）
#   3) Quote 生成软件链（云侧 attestation/QGS，见各云方案）
# 本脚本探测 1+2+3 的就绪度，用于判断是否可进入 TDX enclave 接入开发。
#
# 用法: sudo bash scripts/check-tdx-vm.sh   （dmesg/lsmod 需 root）
set -uo pipefail

PASS=0; FAIL=0
ok()   { echo "[PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }

echo "===== 1. CPU TDX guest 标志 ====="
if lscpu | grep -qi tdx_guest; then
    ok "lscpu 含 tdx_guest（TD 实例已生效）"
else
    bad "未见 tdx_guest —— 非机密实例或未按 TD 创建"
fi

echo "===== 2. TDX guest 驱动 /dev/tdx_guest ====="
if [[ -c /dev/tdx_guest ]]; then
    ok "/dev/tdx_guest 存在（字符设备）"
else
    bad "缺 /dev/tdx_guest —— 内核未开 CONFIG_INTEL_TDX_GUEST 或非 TD 实例"
fi

echo "===== 3. 内核版本 ====="
uname -r
case "$(uname -r)" in
    6.*|5.1[5-9]*|5.2[0-9]*|5.1[0-4]*)
        # 5.15+ 或 6.x 通常含 TDX guest 支持；仍以设备为准
        echo "      （5.15+/6.x 通常具备 TDX guest 支持，最终以 /dev/tdx_guest 为准）" ;;
    *) echo "      （内核较旧，TDX guest 支持存疑）" ;;
esac

echo "===== 4. 内核日志中的 TDX 痕迹 ====="
dmesg 2>/dev/null | grep -i tdx | tail -5 || echo "      （无 dmesg 权限或空，可 sudo 重跑）"

echo "===== 5. 已加载 TDX 模块 ====="
lsmod 2>/dev/null | grep -i tdx || echo "      （无独立 tdx 模块输出；guest 驱动可为内建）"

echo "===== 6. Quote/证明工具链探测（可选组件） ====="
for tool in tdx-attest qgs tdx-dcap-quote-verify tdx-tools snpguest; do
    if command -v "$tool" >/dev/null 2>&1; then
        ok "找到 $tool"
    fi
done
echo "      （此步为空属正常：Quote 生成链按云方案后续安装）"

echo
echo "===== 结论 ====="
if [[ $FAIL -eq 0 ]]; then
    echo "环境就绪：CPU flag + /dev/tdx_guest 齐备 → 可进入 TDX enclave 接入开发（读 tdx_guest 出 TDREPORT + 云侧 Quote/验证链）。"
    echo "下一步参考：阿里云官方《构建 TDX 机密计算环境》远程证明示例（/dev/tdx_guest ioctl）做 Quote 冒烟。"
else
    echo "环境未就绪（FAIL=$FAIL）：请确认实例是按「机密虚拟机/TDX」创建（镜像勾选机密 + 对应可用区规格），"
    echo "或联系阿里云确认该实例是否具备 TDX guest 能力。"
fi
exit $FAIL
