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

echo "===== 2. TDX quote 通道（ConfigFS TSM 优先，/dev/tdx_guest 回退） ====="
# 探测顺序与 tee-infer enclave_tdx.go 的 openTdxQuoteProvider 一致：ConfigFS TSM 优先。
# 注意：新内核（≥6.7 / Alinux4）只有 ConfigFS TSM，无 /dev/tdx_guest——
# 只查设备会把就绪环境误判为未就绪。
tsm_ok=0
if [[ -d /sys/kernel/config/tsm/report ]]; then
    ok "/sys/kernel/config/tsm/report 存在（ConfigFS TSM，go-configfs-tsm 首选）"
    tsm_ok=1
else
    echo "      （无 ConfigFS TSM：内核 <6.7 或 configfs 未挂载 → 回落设备驱动）"
fi
if [[ -c /dev/tdx_guest || -c /dev/tdx-guest ]]; then
    ok "/dev/tdx_guest 或 /dev/tdx-guest 存在（字符设备回退通道）"
else
    echo "      （无 tdx_guest 设备；若上面 ConfigFS TSM 存在则可继续）"
fi
if [[ $tsm_ok -eq 1 || -c /dev/tdx_guest || -c /dev/tdx-guest ]]; then
    ok "至少一条 quote 通道可用（tee -enclave tdx 可构造飞地）"
else
    bad "无任何 TDX quote 通道 —— tee -enclave tdx 构造会失败（fail-fast，符合设计）"
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
echo "===== 7. GPU-TEE（NVIDIA 机密计算）就绪度探测 ====="
# 仅 GPU-TEE 实例相关；CPU-TEE 实例无 nvidia-smi 属预期，不计 FAIL。
if command -v nvidia-smi >/dev/null 2>&1; then
    ok "nvidia-smi 可用（驱动已安装）"
    nvidia-smi --query-gpu=name,driver_version,compute_cap --format=csv,noheader 2>/dev/null | sed 's/^/      GPU: /'
    cc=$(nvidia-smi -q 2>/dev/null | grep -i "Confidential Compute" | head -1 | sed 's/.*: *//')
    if [[ -n "$cc" ]]; then
        echo "      Confidential Compute 状态: $cc"
        case "$cc" in
            On|Enabled|Ready) ok "GPU 机密计算已启用（CC On）" ;;
            *) echo "      （CC 未启用：需 CC 能力卡 + 宿主已启用；VM 内可试 nvidia-smi conf-compute -srs 1 后重启）" ;;
        esac
    else
        echo "      （nvidia-smi 未报告 Confidential Compute 字段：非 CC 能力卡或驱动过旧）"
    fi
else
    echo "      （无 nvidia-smi：CPU-TEE 实例属预期；GPU-TEE 实例需先安装 GPU 驱动）"
fi

echo
echo "===== 结论 ====="
if [[ $FAIL -eq 0 ]]; then
    echo "环境就绪：CPU tdx_guest 标志 + quote 通道（ConfigFS TSM 或 /dev/tdx_guest）齐备"
    echo "  → 可进入 TDX enclave 真机验证（tee-infer -enclave tdx 出真 Quote；再由 scripts/tee-vm-verify.ps1 从本机做证明链/密态 E2E/性能验收）。"
    echo "下一步：阿里云官方《构建 TDX 机密计算环境》远程证明示例（/dev/tdx_guest ioctl）做 Quote 冒烟。"
else
    echo "环境未就绪（FAIL=$FAIL）：请确认实例是按「机密虚拟机/TDX」创建（镜像勾选机密 + 对应可用区规格），"
    echo "或联系云厂商确认该实例是否具备 TDX guest 能力。"
fi
exit $FAIL
