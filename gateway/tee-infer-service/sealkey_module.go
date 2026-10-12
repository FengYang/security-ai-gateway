package main

// sealkey_module.go —— 密封密钥的模块 KEK 路径（P1-5 M4，SealKeySource 第四实现）。
//
// 设计口径（R-16 状态更新，2026-10-12）：P1-8 T4 已落地 SealKeySource 接口
// （Load() 返回密封密钥材料、调用方负责零化）。本实现把该语义扩展为 sm-module
// 档的**模块对象 token**：
//   - enclave 的 Seal/Unseal 经 cryptoProvider 执行 → AEAD 在**模块内**完成
//     （C-4：适配层不自研密码；C-5：密封密钥不以明文形态参与 at-rest）；
//   - Load 返回值为模块对象 token（不透明引用，B-6.1-4）——调用方仅将其传给
//     cryptoProvider.Seal/Open，**不得**当作明秘密使用（token 不含密钥字节）。
//
// 来源优先级：
//  ① OTPMASK_MODULE_SEAL_KEY（env，hex，16B）：导入既有密封密钥——兼容 dev/CI
//     确定性与既有 env 部署形态的模块化迁移（fail-closed：hex/长度/导入失败即拒）；
//  ② 模块内生成（首次引导）：生产后端（SDF/PKCS#11）的持久对象保证重启复用；
//     mock 后端为进程内存语义（重启重建，仅功能验证）。
//     ⚠️ 生产重启复用"按 alias 查找持久对象"待后端持久查找 API（S3-b 真机期补）。
//
// 历史密钥环：模块路径暂不支持（多对象环待持久查找 API）；非模块档不受影响
// （既有 loadSealKeyHistory 路径零改动）。

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"

	cryptopmodule "security-ai-gateway/gateway/cryptop/module"
)

// moduleSealKeyEnv 环境导入的密封密钥（hex；16B = SM4-128）。
const moduleSealKeyEnv = "OTPMASK_MODULE_SEAL_KEY"

// moduleSealKeyAlias 模块内密封密钥对象名（生产持久对象 alias）。
const moduleSealKeyAlias = "otpmask/seal/v1"

// moduleSealKeySource 密封密钥的模块 KEK 路径（token 语义）。
type moduleSealKeySource struct {
	backend cryptopmodule.ModuleBackend
}

// NewModuleSealKeySource 构造模块密封密钥源（backend 为 sm-module 模块后端）。
func NewModuleSealKeySource(backend cryptopmodule.ModuleBackend) *moduleSealKeySource {
	return &moduleSealKeySource{backend: backend}
}

// Load 返回密封密钥的**模块对象 token**（非明文字节；B-6.1-4）。
//
// fail-closed：env 非法 / 导入失败 / 生成失败 → 错误，绝不回退随机（C-3 同构）。
func (s *moduleSealKeySource) Load(_ context.Context) ([]byte, error) {
	if v := os.Getenv(moduleSealKeyEnv); v != "" {
		k, err := hex.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("sealkey: %s hex 解码失败", moduleSealKeyEnv)
		}
		tok, err := s.backend.ImportKey("sm4-128", k, moduleSealKeyAlias)
		if err != nil {
			return nil, fmt.Errorf("sealkey: 导入密封密钥入模块失败: %w", err)
		}
		return tok, nil
	}
	tok, err := s.backend.GenerateKey("sm4-128", moduleSealKeyAlias)
	if err != nil {
		return nil, fmt.Errorf("sealkey: 模块内生成密封密钥失败: %w", err)
	}
	return tok, nil
}

// 编译期契约保证（第四实现；不改变 P1-8 T4 的接口与既有实现）。
var _ SealKeySource = (*moduleSealKeySource)(nil)
