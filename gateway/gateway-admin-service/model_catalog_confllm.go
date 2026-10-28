// Package main — 模型目录密态富化（T04 §2 model_catalog_confllm.go）。
//
// 职责：在 model_catalog.go 的 handleModels 中，对每一行 ai-route 上游富化密态 wire 7 字段
// （confidentialityClass / attestation / attestationVerdict / verificationStatus /
// dataRetention / deployment / connectivity），并应用 managed→A override 硬护栏（§7.5 / §7.11 B2）。
//
// 设计要点：
//   - 单一事实源（§7.5.1）：wire 7 字段一律由 meta.ToWireMetadata 构造，本文件**不手抄**
//     任何 json tag 或举证常量，与 /v1/confllm/models 共用同一归一规则，杜绝两侧漂移；
//   - 密态字段是一等公民，缺省 unknown（绝不臆测密态等级）；
//   - 富化来源 = confllm 全局注册表中按 entry.Provider 匹配的运行期实例 Metadata()；
//     老 CR / 未匹配 → unknown（向后兼容，不影响既有 3 个 model_catalog 测试）；
//   - managed→A override 仅当 deployment=managed 且启动期加载了厂商书面证明引用
//     （ADMIN_CONFLLM_OVERRIDES_JSON，且必须 https:// 开头）才提升为 A；引用合法时
//     verification="claim-with-reference-unverified"（引用≠已验证，IsVerified 恒 false）；
//     引用缺失/非 https → 保持 unknown（fail-closed，绝不静默升级密态等级）。
package main

import (
	"log"

	"security-ai-gateway/gateway/confllm-adapter"
	"security-ai-gateway/gateway/confllm-adapter/meta"
)

// enrichWithConfidentiality 富化模型目录行的密态四字段（§7.5 / §7.11 B2）。
//
// 纯只读：仅读 confllm 注册表，不触发任何网络调用；匹配依据 = 运行期实例 ID
// 与 CR provider id 对齐（由 confllm_wire.go 的 ADMIN_CONFLLM_PROVIDERS_JSON 装配）。
func enrichWithConfidentiality(entry *modelRouteEntry) {
	def := meta.DefaultMeta()

	// 内部 meta 起点：老 CR 可能已声明部分字段（如 class=C），未声明的归并为 unknown。
	cur := meta.ConfidentialityMeta{
		ConfidentialityClass: nzMetaStr(entry.ConfidentialityClass, def.ConfidentialityClass),
		Attestation:          nzMetaStr(entry.Attestation, def.Attestation),
		DataRetention:        nzMetaStr(entry.DataRetention, def.DataRetention),
		Deployment:           nzMetaStr(entry.Deployment, def.Deployment),
		Verification:         meta.Verification(nzMetaStr(entry.Verification, string(def.Verification))),
	}

	// 连通性举证缺省（PRD P0-3 举证边界）：老 CR / 未匹配也必须出现，恒 never-tested。
	// 红线：即便后续 managed→A override 提升 class，也不得升级
	// attestationVerdict / verificationStatus / connectivity 这三项。
	connectivity := meta.ConnNeverTested

	p, ok := confllm.GlobalRegistry.Lookup(entry.Provider)
	if !ok {
		// 老 CR 无密态厂商匹配 → 保持 unknown（wire 举证字段已置缺省）。
		entry.WireMetadata = meta.ToWireMetadata(cur, connectivity)
		entry.Verification = string(cur.Verification)
		return
	}
	m := p.Metadata()
	cur.ConfidentialityClass = nzMetaStr(m.ConfidentialityClass, def.ConfidentialityClass)
	cur.Attestation = nzMetaStr(m.Attestation, def.Attestation)
	cur.DataRetention = nzMetaStr(m.DataRetention, def.DataRetention)
	cur.Deployment = nzMetaStr(m.Deployment, def.Deployment)
	cur.Verification = meta.Verification(nzMetaStr(string(m.Verification), string(def.Verification)))

	// managed→A 硬护栏（§7.11 B2）：仅 managed 形态 + https 书面证明引用方可提升为 A。
	if m.Deployment == meta.DeployManaged {
		if ov, has := confllmManagedOverrides[entry.Provider]; has {
			upgraded, err := meta.ApplyManagedToAOverride(m, m.Deployment, &ov)
			if err != nil {
				// 硬护栏：证明引用缺失/非 https → 拒绝 override，保持 unknown（fail-closed）。
				log.Printf("[models] confllm provider=%s managed→A override 被拒（§7.11 B2）：%v",
					entry.Provider, err)
			} else {
				cur.ConfidentialityClass = upgraded.ConfidentialityClass
				cur.Attestation = upgraded.Attestation
				// 引用≠已验证：目录登记 claim-with-reference-unverified（IsVerified 恒 false）。
				cur.Verification = upgraded.Verification
			}
		}
	}

	// 单一事实源（§7.5.1）：wire 7 字段一律由 meta.ToWireMetadata 构造 ——
	// attestationVerdict 恒 unknown、verificationStatus 恒 claim-unverified，
	// 内部中间态（claim-with-reference-unverified）只留在结构体上、绝不进 wire。
	entry.WireMetadata = meta.ToWireMetadata(cur, connectivity)
	entry.Verification = string(cur.Verification)
}

// nzMetaStr 空字符串归并为 fallback（密态字段缺省 unknown）。
func nzMetaStr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
