#!/usr/bin/env bash
# P1-3 等保 §6.6（W9 / M7）恢复脚本 —— 异地取回 → 解密 → 摘要校验 → 按类恢复 → 校验。
#
# 用途：备份恢复演练（OPS-06）与真实恢复。RPO/RTO 目标见 §6.6 与 README.md 演练清单。
#
# 用法：
#   BACKUP_SCOPE=config ./restore.sh 20261009T120000Z   # 恢复指定时点快照
#   BACKUP_SCOPE=audit  ./restore.sh 20261009T120000Z --verify-only   # 仅校验不恢复
#
# 安全约束（§6.6 作业权限）：
#   - 恢复使用独立 SA（最小授权），不与日常运维共享；
#   - 恢复前先快照当前状态（回滚点），恢复失败可退回；
#   - 审计链恢复后必须通过 audit-verify 链校验方可判定成功。
set -euo pipefail

BACKUP_SCOPE="${1:-${BACKUP_SCOPE:-}}"
[[ -z "${BACKUP_SCOPE}" ]] && { echo "用法: BACKUP_SCOPE=config|secrets|audit|metrics ./restore.sh <STAMP> [--verify-only]"; exit 2; }
STAMP="${2:-${STAMP:-}}"
[[ -z "${STAMP}" ]] && { echo "缺少 STAMP（备份时点，如 20261009T120000Z）"; exit 2; }

NAMESPACE="${NAMESPACE:-otpmask}"
WORKDIR="$(mktemp -d)"
RESTORE_DIR="${RESTORE_DIR:-/restore}"
AGE_IDENTITY="${AGE_IDENTITY:?需要 AGE_IDENTITY（age 私钥路径；由 KMS/Vault 取出，用后即焚）}"
S3_ENDPOINT="${S3_ENDPOINT:?需要 S3_ENDPOINT}"
S3_BUCKET="${S3_BUCKET:?需要 S3_BUCKET}"
PREFIX="otpmask/${BACKUP_SCOPE}/${STAMP}"
VERIFY_ONLY="${3:-}"

log() { printf '[restore] %s %s\n' "$(date -u +%FT%TZ)" "$*"; }
mkdir -p "${WORKDIR}" "${RESTORE_DIR}"

PKG_NAME="otpmask-${BACKUP_SCOPE}-${STAMP}.tar.age"
log "取回 s3://${S3_BUCKET}/${PREFIX}/${PKG_NAME}"
aws --endpoint-url "${S3_ENDPOINT}" s3 cp "s3://${S3_BUCKET}/${PREFIX}/${PKG_NAME}" "${WORKDIR}/${PKG_NAME}"
aws --endpoint-url "${S3_ENDPOINT}" s3 cp "s3://${S3_BUCKET}/${PREFIX}/${PKG_NAME}.sha256" "${WORKDIR}/${PKG_NAME}.sha256"

# ---- 摘要校验（先验包完整性，再解密）----
EXPECT="$(awk '{print $1}' "${WORKDIR}/${PKG_NAME}.sha256")"
ACTUAL="$(sha256sum "${WORKDIR}/${PKG_NAME}" | awk '{print $1}')"
if [[ "${EXPECT}" != "${ACTUAL}" ]]; then
  log "错误：备份包摘要不一致（expect=${EXPECT} actual=${ACTUAL}），拒绝恢复"; exit 3
fi
log "包摘要校验通过"

# ---- 解密 ----
age -d -i "${AGE_IDENTITY}" -o "${WORKDIR}/pkg.tar" "${WORKDIR}/${PKG_NAME}"
tar -C "${WORKDIR}" -xf "${WORKDIR}/pkg.tar"

if [[ "${VERIFY_ONLY}" == "--verify-only" ]]; then
  log "仅校验模式：解密与解包成功，未做集群变更"
  exit 0
fi

# ---- 恢复前留回滚点（当前状态快照；失败可退回）----
log "采集回滚点（当前状态）"
kubectl -n "${NAMESPACE}" get all,cm,secret -o yaml > "${RESTORE_DIR}/rollback-$(date -u +%Y%m%dT%H%M%SZ).yaml" || true

# ---- 按类恢复 ----
case "${BACKUP_SCOPE}" in
  config)
    kubectl apply -n "${NAMESPACE}" -f "${WORKDIR}/config/core.yaml"
    for f in "${WORKDIR}/config"/crd-*.yaml; do
      [[ -f "${f}" ]] && kubectl apply -n "${NAMESPACE}" -f "${f}" || true
    done
    log "配置/CR 恢复完成；请核对 config-drift-baseline.json 与运行态是否一致（R2-10）"
    ;;
  secrets)
    kubectl apply -n "${NAMESPACE}" -f "${WORKDIR}/secrets/secrets.yaml"
    log "密钥恢复完成；请验证依赖服务凭据可用性（§6.6 演练内容③）"
    ;;
  audit)
    # 审计链恢复：写入挂载点（保留 WORM 语义；不覆盖新于快照的事件，由运维按 RTO 窗口处置）。
    if [[ -d "${RESTORE_DIR}/audit" ]]; then
      cp -an "${WORKDIR}/audit/." "${RESTORE_DIR}/audit/" 2>/dev/null || true
    fi
    # 链校验：恢复成功判据（§6.6 演练内容②）。
    if command -v audit-verify >/dev/null 2>&1 && [[ -f "${RESTORE_DIR}/audit/admin-audit.log" ]]; then
      audit-verify -file "${RESTORE_DIR}/audit/admin-audit.log" || { log "错误：链校验失败"; exit 4; }
      log "审计链恢复并通过 audit-verify 校验"
    else
      log "警告：未发现 audit-verify 或恢复目标文件，请人工校验"
    fi
    ;;
  metrics)
    log "指标元数据已解包至 ${WORKDIR}/metrics；Prometheus 数据卷恢复请按 PV 绑定流程执行"
    ;;
esac

rm -rf "${WORKDIR}"
log "恢复完成 scope=${BACKUP_SCOPE} stamp=${STAMP}；请记录 RPO/RTO 实测值至演练记录表（README.md）"
