package main

// TDX 飞地实现（甲路线真机）：阿里云机密 VM（g8i/g9i）。
//
// Quote 生成经 go-tdx-guest（龙蜥/阿里云官方推荐库）：ConfigFS TSM 优先，
// /dev/tdx_guest 设备回退。Quote 内嵌 PCK 证书链与 MRTD/RTMR 度量，
// 可被远端独立验证（Intel DCAP 证书链 / tee-appraisal-tool）。
//
// 环境前提（check-tdx-vm.sh 探测）：
//  1. CPU tdx_guest 标志（实例按「机密虚拟机」模式创建）
//  2. /sys/kernel/config/tsm/report（Alinux4/Ubuntu24+）或 /dev/tdx_guest（Alinux3）

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/go-tdx-guest/client"
)

// tdxSealKeyEnv TDX 密封密钥注入环境变量（32 字节 hex）。
// v1 策略：环境变量或随机生成；升级路径：由 TDX 能力派生（如 TDREPORT 私有字段）。
const tdxSealKeyEnv = "OTPMASK_TDX_SEAL_KEY"

// TdxEnclave 真 TDX 飞地。
type TdxEnclave struct {
	sealKey  []byte            // 密封密钥（Seal/Unseal）
	signKey  *ecdsa.PrivateKey // 证明签名密钥（会话级，进程内）
	measure  []byte            // 进程内测量值（真完整性证据在 Quote 的 MRTD/RTMR）
	provider any               // client.QuoteProvider（ConfigFS）或 client.Device（/dev/tdx_guest）
}

// NewTdxEnclave 构造真 TDX 飞地；构造期探测 quote 通道，不可用即失败（fail-closed，
// main.go 启动即 Fatal，避免静默降级 mock）。
func NewTdxEnclave() (*TdxEnclave, error) {
	provider, err := openTdxQuoteProvider()
	if err != nil {
		return nil, err
	}
	sealKey, err := loadSealKey(tdxSealKeyEnv)
	if err != nil {
		return nil, err
	}
	signKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("enclave: 生成证明签名密钥失败: %w", err)
	}
	// 测量值：摘要常量（跨实例稳定，与 mock 同策略）。真完整性证据在 Quote 的
	// MRTD/RTMR（由验证方解析 Quote 校验）；升级路径：从 TDREPORT 读取 RTMR 摘要。
	measure := cryptoProvider.Hash([]byte("tdx-enclave-measurement:v1"))
	return &TdxEnclave{
		sealKey:  sealKey,
		signKey:  signKey,
		measure:  measure[:],
		provider: provider,
	}, nil
}

// openTdxQuoteProvider 探测 TDX quote 通道：ConfigFS TSM 优先，设备驱动回退。
// 两者皆不可用（非机密实例 / 驱动缺失）返回明确错误。
func openTdxQuoteProvider() (any, error) {
	if qp, err := client.GetQuoteProvider(); err == nil {
		if qerr := qp.IsSupported(); qerr == nil {
			return qp, nil
		}
	}
	if dev, err := client.OpenDevice(); err == nil {
		return dev, nil
	}
	return nil, errors.New("enclave: 无可用 TDX quote 通道（需机密虚拟机实例：ConfigFS tsm 或 /dev/tdx_guest）")
}

// Platform 返回平台标识。
func (e *TdxEnclave) Platform() string { return "tdx" }

// Measure 返回进程内测量值。
func (e *TdxEnclave) Measure() ([]byte, error) {
	out := make([]byte, len(e.measure))
	copy(out, e.measure)
	return out, nil
}

// Seal 经 cryptop.Provider 密封（与 mock 同构；密钥经 OTPMASK_TDX_SEAL_KEY 注入）。
func (e *TdxEnclave) Seal(plaintext []byte, context string) ([]byte, error) {
	return sealWithContext(e.sealKey, plaintext, context)
}

// Unseal 解封，验证 AAD 和 AEAD tag。
func (e *TdxEnclave) Unseal(ciphertext []byte, context string) ([]byte, error) {
	return unsealWithContext(e.sealKey, ciphertext, context)
}

// tdxReportData 把握手绑定材料扩展为 TDX REPORTDATA（64 字节）：
// 前 32B = H(nonce‖server_pub)（超长截断），余置零；验证方校验前缀绑定（P1b）。
func tdxReportData(reportData []byte) [64]byte {
	var rd [64]byte
	if len(reportData) > 32 {
		reportData = reportData[:32]
	}
	copy(rd[:], reportData)
	return rd
}

// Attest 生成真 TDX 证明：reportData 注入 Quote 的 REPORTDATA 字段（防握手
// 公钥替换），Quote 为硬件签名证据（含 PCK 证书链）；签名结构与 mock 对齐
// （客户端验签逻辑共用）。
func (e *TdxEnclave) Attest(challenge, reportData []byte) (*AttestationProof, error) {
	if len(reportData) == 0 {
		return nil, errors.New("enclave: report_data 为空（握手绑定材料必填）")
	}
	quote, err := client.GetRawQuote(e.provider, tdxReportData(reportData))
	if err != nil {
		return nil, fmt.Errorf("enclave: TDX Quote 生成失败: %w", err)
	}
	signingPub, sig, err := signProofBinding(e.signKey, reportData)
	if err != nil {
		return nil, err
	}
	return &AttestationProof{
		Nonce:      challenge,
		Platform:   "tdx",
		ReportData: append([]byte(nil), reportData...),
		Quote:      quote,
		Measurements: map[string]string{
			"app_hash":    hex.EncodeToString(e.measure),
			"runtime":     "tdx",
			"quote_bytes": strconv.Itoa(len(quote)),
		},
		SigningKey: signingPub,
		Signature:  sig,
	}, nil
}
