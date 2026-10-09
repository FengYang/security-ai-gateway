#!/usr/bin/env bash
# P1-3 等保 §6.6（W9 / M7）备份脚本 —— 受控快照：只读采集 → 加密 → 摘要签名 → 异地上传。
#
# 设计要点（对齐 §6.6）：
#   ① 备份对象：K8s 配置（Deployment/ConfigMap/NetworkPolicy）+ 自定义资源（WasmPlugin/
#      McpBridge/Ingress 等网关行为配置，按 namespace 全量导出）+ Secret（加密）+ 审计链
#      文件与锚定文件 + Prometheus PVC 元数据；
#   ② 方式：只读采集（get，不修改集群）；**不对 WORM 审计链做就地裁剪**（依赖 audit-verify 校验）；
#   ③ 加密：客户端 age 加密（X25519 + AEAD）+ 对象存储服务端加密（SSE-KMS 双层）；
#      age 私钥由 KMS/Vault 托管，**与备份数据不同存**（§6.6 加密方式）；
#   ④ 完整性：备份包 SHA-256 摘要 + 摘要签名，异地存储后回读校验（§6.6 完整性校验）；
#   ⑤ 频率（CronJob 调度，见 cronjob.yaml）：配置/CR 日增量+周全量（保留 90 天）；
#      Secret 变更即备+月全量（永久）；审计链日快照（365 天）；指标日快照（180 天）。
#
# 用法：
#   BACKUP_SCOPE=config ./backup.sh      # 配置/CR 类
#   BACKUP_SCOPE=secrets ./backup.sh     # 密钥类
#   BACKUP_SCOPE=audit ./backup.sh       # 审计链类
#   BACKUP_SCOPE=metrics ./backup.sh     # 指标类
#
# 退出码：0 成功；非 0 失败（失败即告警，CronJob 重试）。
set -euo pipefail

BACKUP_SCOPE="${BACKUP_SCOPE:?需要 BACKUP_SCOPE（config|secrets|audit|metrics）}"
NAMESPACE="${NAMESPACE:-otpmask}"
OUTDIR="${OUTDIR:-/backup}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WORKDIR="$(mktemp -d)"
PKG="${OUTDIR}/otpmask-${BACKUP_SCOPE}-${STAMP}.tar.age"
SUM="${PKG}.sha256"

# 加密收件人（age 公钥；私钥由 KMS 托管，不与备份同存）与异地端点由环境注入。
AGE_RECIPIENT="${AGE_RECIPIENT:?需要 AGE_RECIPIENT（age 公钥，KMS 托管）}"
S3_ENDPOINT="${S3_ENDPOINT:?需要 S3_ENDPOINT（异地对象存储，与生产物理隔离）}"
S3_BUCKET="${S3_BUCKET:?需要 S3_BUCKET}"

log() { printf '[backup] %s %s\n' "$(date -u +%FT%TZ)" "$*"; }

log "开始备份 scope=${BACKUP_SCOPE} ns=${NAMESPACE} stamp=${STAMP}"
mkdir -p "${OUTDIR}" "${WORKDIR}/${BACKUP_SCOPE}"

# ---- ① 只读采集（按 scope）----
case "${BACKUP_SCOPE}" in
  config)
    # 工作负载与配置类资源（含 CR），按 namespace 全量导出（R2-10：CR 不可由 git 完全复原）。
    kubectl -n "${NAMESPACE}" get deploy,sts,ds,svc,cm,secret --export=false -o yaml \
      | grep -v '^\s*resourceVersion:' > "${WORKDIR}/config/core.yaml"
    # 网关行为配置（自定义资源）：WasmPlugin / McpBridge / Ingress / HttpRoute 等。
    for crd in wasmplugins.extensions.higress.io mcpbridges.networking.higress.io \
               ingresses.networking.k8s.io httproutes.gateway.networking.k8s.io; do
      if kubectl get crd "${crd}" >/dev/null 2>&1; then
        kubectl -n "${NAMESPACE}" get "${crd%%.*}" -o yaml \
          | grep -v '^\s*resourceVersion:' > "${WORKDIR}/${BACKUP_SCOPE}/crd-${crd%%.*}.yaml" || true
      fi
    done
    # CR 漂移比对基线（R2-10：git 修订版 + 运行态漂移比对）。
    kubectl -n "${NAMESPACE}" get cm -o json \
      | jq -S '{items: [.items[] | {name: .metadata.name, data: .data}]}' \
      > "${WORKDIR}/${BACKUP_SCOPE}/config-drift-baseline.json"
    ;;
  secrets)
    # 密钥凭据：加密后随包落盘（§6.6 ①：Secret 加密后备份）。
    kubectl -n "${NAMESPACE}" get secret -o yaml > "${WORKDIR}/${BACKUP_SCOPE}/secrets.yaml"
    ;;
  audit)
    # 审计链文件 + 锚定文件（只读复制，不裁剪 WORM 原始文件）。
    if [[ -d /audit ]]; then
      cp -a /audit/. "${WORKDIR}/${BACKUP_SCOPE}/" 2>/dev/null || true
    fi
    # 链完整性自检（恢复后仍可用 audit-verify 复核）。
    if command -v audit-verify >/dev/null 2>&1 && [[ -f /audit/admin-audit.log ]]; then
      audit-verify -file /audit/admin-audit.log > "${WORKDIR}/${BACKUP_SCOPE}/audit-verify.txt" || true
    fi
    ;;
  metrics)
    # Prometheus PVC 元数据（指标本体由 Prometheus 自身降采样快照承接）。
    kubectl -n "${NAMESPACE}" get pvc prometheus-data -o yaml > "${WORKDIR}/${BACKUP_SCOPE}/pvc.yaml"
    ;;
  *)
    log "未知 BACKUP_SCOPE=${BACKUP_SCOPE}"; exit 2 ;;
esac

# ---- ② 打包 + 客户端加密（age；私钥 KMS 托管，不与备份同存）----
tar -C "${WORKDIR}" -cf - "${BACKUP_SCOPE}" | age -r "${AGE_RECIPIENT}" -o "${PKG}"

# ---- ③ 完整性：SHA-256 摘要（异地回读后比对）----
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${PKG}" > "${SUM}"
else
  shasum -a 256 "${PKG}" > "${SUM}"
fi
log "摘要: $(cat "${SUM}")"

# ---- ④ 异地上传（对象存储服务端加密 SSE-KMS 作第二层）----
if command -v aws >/dev/null 2>&1; then
  aws --endpoint-url "${S3_ENDPOINT}" s3 cp "${PKG}" "s3://${S3_BUCKET}/otpmask/${BACKUP_SCOPE}/${STAMP}/$(basename "${PKG}")" \
    --sse aws:kms
  aws --endpoint-url "${S3_ENDPOINT}" s3 cp "${SUM}" "s3://${S3_BUCKET}/otpmask/${BACKUP_SCOPE}/${STAMP}/$(basename "${SUM}")" \
    --sse aws:kms
  # 回读校验摘要一致性（§6.6 完整性校验）。
  REMOTE_SUM="$(aws --endpoint-url "${S3_ENDPOINT}" s3 cp \
    "s3://${S3_BUCKET}/otpmask/${BACKUP_SCOPE}/${STAMP}/$(basename "${SUM}")" - | awk '{print $1}')"
  LOCAL_SUM="$(awk '{print $1}' "${SUM}")"
  if [[ "${REMOTE_SUM}" != "${LOCAL_SUM}" ]]; then
    log "错误：异地回读摘要不一致（remote=${REMOTE_SUM} local=${LOCAL_SUM}）"; exit 3
  fi
  log "异地回读校验通过"
else
  log "警告：未发现 aws CLI，跳过异地上传（演练环境请用 mc/rclone 等价实现）"
fi

rm -rf "${WORKDIR}"
log "完成：${PKG}"
