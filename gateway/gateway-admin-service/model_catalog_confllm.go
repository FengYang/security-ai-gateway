// Package main — 模型目录密态富化（T04 §2 model_catalog_confllm.go）。
//
// 职责：在 model_catalog.go 的 handleModels 中，对每一行 ai-route 上游富化密态四字段
// （confidentialityClass / attestation / dataRetention / deployment），并应用
// managed→A override 硬护栏（§7.5 / §7.11 B2）。
//
// 设计要点：
//   - 密态四字段是一等公民，缺省 unknown（绝不臆测密态等级）；
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
	entry.ConfidentialityClass = nzMetaStr(entry.ConfidentialityClass, def.ConfidentialityClass)
	entry.Attestation = nzMetaStr(entry.Attestation, def.Attestation)
	entry.DataRetention = nzMetaStr(entry.DataRetention, def.DataRetention)
	entry.Deployment = nzMetaStr(entry.Deployment, def.Deployment)
	entry.Verification = nzMetaStr(entry.Verification, string(def.Verification))

	p, ok := confllm.GlobalRegistry.Lookup(entry.Provider)
	if !ok {
		return // 老 CR 无密态厂商匹配 → 保持 unknown
	}
	m := p.Metadata()
	entry.ConfidentialityClass = nzMetaStr(m.ConfidentialityClass, def.ConfidentialityClass)
	entry.Attestation = nzMetaStr(m.Attestation, def.Attestation)
	entry.DataRetention = nzMetaStr(m.DataRetention, def.DataRetention)
	entry.Deployment = nzMetaStr(m.Deployment, def.Deployment)
	entry.Verification = nzMetaStr(string(m.Verification), string(def.Verification))

	// managed→A 硬护栏（§7.11 B2）：仅 managed 形态 + https 书面证明引用方可提升为 A。
	if m.Deployment != meta.DeployManaged {
		return
	}
	ov, has := confllmManagedOverrides[entry.Provider]
	if !has {
		return
	}
	upgraded, err := meta.ApplyManagedToAOverride(m, m.Deployment, &ov)
	if err != nil {
		// 硬护栏：证明引用缺失/非 https → 拒绝 override，保持 unknown（fail-closed）。
		log.Printf("[models] confllm provider=%s managed→A override 被拒（§7.11 B2）：%v",
			entry.Provider, err)
		return
	}
	entry.ConfidentialityClass = upgraded.ConfidentialityClass
	entry.Attestation = upgraded.Attestation
	// 引用≠已验证：目录登记 claim-with-reference-unverified（IsVerified 恒 false）。
	entry.Verification = string(upgraded.Verification)
}

// nzMetaStr 空字符串归并为 fallback（密态字段缺省 unknown）。
func nzMetaStr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
