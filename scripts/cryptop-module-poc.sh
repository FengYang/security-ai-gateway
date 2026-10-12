#!/usr/bin/env bash
# =============================================================================
# cryptop-module-poc.sh —— P1-5 M6-1：认证密码模块选型 POC 运行脚本
#
# 依据：《GA-AI网关能力补齐方案--P1--国密S3-S4认证模块与密评》
#       §5.3「POC 必测项」①-⑨、§6.4 配置项、§4.3 M6-1/M6-2；
#       风险 R-3（性能不达标）/ R-13（并发会话配额）/ GM2-03（随机数质量）。
#
# 目的：对候选厂商模块逐家执行必测项，**以实测替换厂商标称值**，产出可复核的
#       POC 报告（Markdown），供 §5.3 选型打分矩阵引用。
#
# 用法：
#   scripts/cryptop-module-poc.sh --vendor <厂商名> --backend sdf|pkcs11 \
#         [--lib /abs/path/vendor.so] [--slot N] [--pin-ref ENV_NAME] [--out <report.md>]
#   # 无真实模块时的适配层基线（mock，非厂商实测，报告会如实标注）：
#   scripts/cryptop-module-poc.sh --vendor baseline --backend mock
#
# 安全（R-S3-2）：登录口令只经**引用名**（MODULE_PIN_REF）传递，绝不传入命令行、
#                 环境字面值或写入报告。
#
# 退出码：0 完成（含 SKIP）；1 参数/环境错误；2 存在 FAIL 项。
# =============================================================================
set -euo pipefail

# ---- 参数解析 ----
VENDOR=""; BACKEND=""; LIB=""; SLOT=""; PIN_REF=""; OUT=""
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() { sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --vendor)  VENDOR="${2:-}"; shift 2 ;;
    --backend) BACKEND="${2:-}"; shift 2 ;;
    --lib)     LIB="${2:-}"; shift 2 ;;
    --slot)    SLOT="${2:-}"; shift 2 ;;
    --pin-ref) PIN_REF="${2:-}"; shift 2 ;;
    --out)     OUT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; usage >&2; exit 1 ;;
  esac
done

[ -n "$VENDOR" ]  || { echo "缺少 --vendor" >&2; exit 1; }
[ -n "$BACKEND" ] || { echo "缺少 --backend" >&2; exit 1; }
case "$BACKEND" in
  sdf|pkcs11|mock) ;;
  *) echo "--backend 须为 sdf|pkcs11|mock，got=$BACKEND" >&2; exit 1 ;;
esac
if [ "$BACKEND" != "mock" ] && [ -z "$LIB" ]; then
  echo "--backend=$BACKEND 必须提供 --lib <厂商 .so 绝对路径>" >&2; exit 1
fi
[ -n "$OUT" ] || OUT="deploy/tlcp/POC-${VENDOR}-$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null || echo report).md"

# ---- 结果收集（pass/fail/skip + 详情）----
declare -A R D
set_res() { R["$1"]="$2"; D["$1"]="$3"; }
final_exit=0
mark_fail() { final_exit=2; }

# ---- 环境探测 ----
HAVE_NM=0; command -v nm >/dev/null 2>&1 && HAVE_NM=1
HAVE_LDD=0; command -v ldd >/dev/null 2>&1 && HAVE_LDD=1
MOCK_BASELINE=0; [ "$BACKEND" = "mock" ] && MOCK_BASELINE=1

echo "== cryptop-module-poc: vendor=$VENDOR backend=$BACKEND =="

# =============================================================================
# ① 接口可用性：库文件存在 + 可加载 + 导出符号（SDF/PKCS#11）
# =============================================================================
if [ "$MOCK_BASELINE" = "1" ]; then
  set_res "iface" "skip" "mock 基线：无厂商库（适配层功能验证）"
else
  if [ ! -f "$LIB" ]; then
    set_res "iface" "fail" "库文件不存在: $LIB"; mark_fail
  else
    load_ok=1; load_detail="库存在"
    if [ "$HAVE_LDD" = "1" ] && ! ldd "$LIB" >/dev/null 2>&1; then
      load_ok=0; load_detail="ldd 解析失败（依赖缺失？）"
    fi
    if [ "$HAVE_NM" = "1" ]; then
      syms=""
      if [ "$BACKEND" = "sdf" ]; then
        for s in SDF_OpenDevice SDF_OpenSession SDF_GenerateRandom; do
          nm -D "$LIB" 2>/dev/null | grep -q " $s\$" && syms="$syms $s✓" || syms="$syms $s✗"
        done
      else
        for s in C_Initialize C_GetFunctionList C_OpenSession; do
          nm -D "$LIB" 2>/dev/null | grep -q " $s\$" && syms="$syms $s✓" || syms="$syms $s✗"
        done
      fi
      load_detail="$load_detail；符号:$syms"
      case "$syms" in *✗*) load_ok=0 ;; esac
    else
      load_detail="$load_detail；无 nm，跳过符号检查"
    fi
    if [ "$load_ok" = "1" ]; then
      set_res "iface" "pass" "$load_detail"
    else
      set_res "iface" "fail" "$load_detail"; mark_fail
    fi
  fi
fi

# =============================================================================
# ② 配置校验（§6.4 / R-S3-1/2/7/11）：经 module 包 Validate（env 驱动）
# =============================================================================
cfg_detail=""
cfg_rc=0
(
  cd "$REPO_ROOT"
  export CRYPTOP_POC=1
  export MODULE_BACKEND="$BACKEND"
  [ "$MOCK_BASELINE" = "1" ] || export MODULE_LIB_PATH="$LIB"
  [ -n "$SLOT" ]   && export MODULE_SLOT="$SLOT"
  [ -n "$PIN_REF" ] && export MODULE_PIN_REF="$PIN_REF"
  go test -mod=mod -run 'TestPOCConfigValidate' -count=1 ./gateway/cryptop/module/ >/dev/null 2>&1
) && cfg_rc=0 || cfg_rc=$?
if [ "$cfg_rc" = "0" ]; then
  set_res "config" "pass" "module 配置校验通过（R-S3-1/2/7/11）"
else
  set_res "config" "fail" "配置校验未通过（退出码 $cfg_rc）；检查 MODULE_* 环境变量"
  mark_fail
fi

# =============================================================================
# ③ 性能基准（必测项①SM4-GCM 吞吐/P99、②SM2 签名 QPS）
#    经 §6.2 适配层 → ModuleBackend；真机即厂商模块，mock 即适配层基线。
# =============================================================================
bench_out=""
(
  cd "$REPO_ROOT"
  export MODULE_BACKEND="$BACKEND"
  [ "$MOCK_BASELINE" = "1" ] || export MODULE_LIB_PATH="$LIB"
  go test -mod=mod -run '^$' -bench 'BenchmarkModule' -benchmem -benchtime=1s ./gateway/cryptop/module/ 2>&1
) > /tmp/poc-bench.$$ 2>&1 || true
if grep -q '^Benchmark' /tmp/poc-bench.$$ 2>/dev/null; then
  bench_out="$(grep -E '^(Benchmark|ok|PASS)' /tmp/poc-bench.$$ | head -20)"
  set_res "bench" "pass" "见报告「基准数据」段"
else
  set_res "bench" "skip" "基准未产出（检查 bench_test.go / 模块可用性）"
fi
rm -f /tmp/poc-bench.$$

# =============================================================================
# ④-⑨ 需真机 / 机构核验项：脚本组织检查步骤，产出「待真机执行」占位
#    （无真实模块时不得编造数据，脚本不代填标称值——§5.3「以实测替换标称值」）
# =============================================================================
if [ "$MOCK_BASELINE" = "1" ]; then
  for k in keysnonexport powercut concurrency randquality protectlevel; do
    set_res "$k" "skip" "需真实模块（mock 基线不产生该数据）"
  done
else
  # 真机环境就绪与否由调用方确认；脚本输出执行指引，不臆造结果。
  set_res "keysnonexport" "todo" "校验 CKA_SENSITIVE=true/CKA_EXTRACTABLE=false/CKA_WRAP 白名单 且 C_GetAttributeValue(CKA_VALUE) 失败（必测项③）"
  set_res "powercut"      "todo" "掉电/拔卡恢复（必测项④）"
  set_res "concurrency"   "todo" "并发会话上限 + P99 退化曲线（必测项⑤⑨，R-13）"
  set_res "randquality"   "todo" "GM/T 0050 启动自检 + 单比特频数/连续运行（必测项⑦，GM2-03）"
  set_res "protectlevel"  "todo" "查认证证书 GM/T 0028 等级 + 侧信道防护等级（必测项⑧，U-S3-3）"
fi

# =============================================================================
# 生成 Markdown 报告
# =============================================================================
ts="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo '-')"
{
  echo "# P1-5 M6 认证密码模块 POC 报告 —— ${VENDOR}"
  echo ""
  echo "> 由 \`scripts/cryptop-module-poc.sh\` 生成（$ts）。**以实测替换厂商标称值**（§5.3）。"
  echo "> $( [ "$MOCK_BASELINE" = "1" ] && echo '⚠ 本次为 **mock 适配层基线**，非厂商实测，禁止用于选型打分或合规声明。' || echo '本次为厂商模块实测环境。')"
  echo ""
  echo "| 项 | 结果 | 详情 |"
  echo "| -- | -- | -- |"
  printf '| ①接口可用性(库/符号) | %s | %s |\n' "${R[iface]:-skip}" "${D[iface]:-}"
  printf '| 配置校验(R-S3-1/2/7/11) | %s | %s |\n' "${R[config]:-skip}" "${D[config]:-}"
  printf '| ①②性能基准 | %s | %s |\n' "${R[bench]:-skip}" "${D[bench]:-}"
  printf '| ③密钥不可导出 | %s | %s |\n' "${R[keysnonexport]:-skip}" "${D[keysnonexport]:-}"
  printf '| ④掉电/拔卡恢复 | %s | %s |\n' "${R[powercut]:-skip}" "${D[powercut]:-}"
  printf '| ⑤⑨并发会话 | %s | %s |\n' "${R[concurrency]:-skip}" "${D[concurrency]:-}"
  printf '| ⑦随机数质量 | %s | %s |\n' "${R[randquality]:-skip}" "${D[randquality]:-}"
  printf '| ⑧防护等级 | %s | %s |\n' "${R[protectlevel]:-skip}" "${D[protectlevel]:-}"
  echo ""
  echo "## 基准数据（必测项①②原始输出）"
  echo ""
  echo '```'
  [ -n "$bench_out" ] && echo "$bench_out" || echo "(未采集)"
  echo '```'
  echo ""
  echo "## 待真机项执行指引"
  echo ""
  echo "- ③ 密钥不可导出：PKCS#11 须**同时**校验 \`CKA_SENSITIVE=true\`、\`CKA_EXTRACTABLE=false\`、\`CKA_WRAP\` 白名单，且 \`C_GetAttributeValue(CKA_VALUE)\` 失败（仅测后者不足，§5.3③）。"
  echo "- ④ 掉电恢复：运行中拔卡/断电，重启后校验密钥对象一致性与服务恢复。"
  echo "- ⑤⑨ 并发会话：调整 \`module_max_sessions\`/\`module_session_queue_size\`，记录 P99 饱和点（R-13）。"
  echo "- ⑦ 随机数质量：执行 GM/T 0050 启动自检 + 分布均匀性/单比特频数/连续运行测试。"
  echo "- ⑧ 防护等级：核验商用密码产品认证证书（GM/T 0028 等级、侧信道防护）。"
  echo ""
  echo "## 结论"
  echo ""
  if [ "$final_exit" = "0" ]; then
    echo "自动化项通过/跳过；**待真机项须补齐后方可进入 §5.3 选型打分**。"
  else
    echo "存在 FAIL 项，**不得进入选型打分**，须先修复或更换候选模块。"
  fi
} > "$OUT"

echo "报告已生成: $OUT"
echo "自动化项结果：iface=${R[iface]:-skip} config=${R[config]:-skip} bench=${R[bench]:-skip}"
exit "$final_exit"
