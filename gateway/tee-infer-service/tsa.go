// tsa.go - 可信时间戳服务
package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/emmansun/gmsm/pkcs7"
	"github.com/emmansun/gmsm/smx509"

	"security-ai-gateway/gateway/cryptop"
)

// tstAlgorithm TST 签名算法标识（P0-4 §5.4.1 组⑥ / §5.2.2「`TST.Algorithm` 版本化」）。
// intl 档保持历史值 `sha256`（**intl TST 逐字节不变**）；sm 档为 `sm3`。
// 验签按 §5.2.2 判定口径分派：**仅** `=="sm3"` 判 SM3；空/其它值一律按 SHA-256（fail-safe）。
func tstAlgorithm() string {
	if cryptoProvider.Profile() == cryptop.ProfileIntl {
		return "sha256"
	}
	return "sm3"
}

// TST 时间戳令牌
type TST struct {
	Version        int    `json:"version"`
	Algorithm      string `json:"algorithm"`
	TimestampNS    int64  `json:"timestamp_ns"`
	MessageImprint string `json:"message_imprint"`
	Signature      string `json:"signature"`
	TSAPublicKey   string `json:"tsa_public_key"`
	Source         string `json:"source"`
}

// TSASigner 时间戳签名接口
type TSASigner interface {
	Sign(messageImprint []byte) (*TST, error)
	Verify(t *TST) error
}

// ---------- MockTSA ----------

// MockTSA 本地 TSA，HMAC-SHA256 自签
type MockTSA struct {
	key []byte
}

func NewMockTSA() (*MockTSA, error) {
	k, err := cryptoProvider.Rand(32)
	if err != nil {
		return nil, fmt.Errorf("tsa: 生成密钥失败: %w", err)
	}
	return &MockTSA{key: k}, nil
}

func (m *MockTSA) Sign(messageImprint []byte) (*TST, error) {
	if len(messageImprint) != cryptoProvider.HashSize() {
		return nil, fmt.Errorf("tsa: message_imprint 须为 %d 字节摘要", cryptoProvider.HashSize())
	}
	mac, merr := hmacByAlg(hashAlgTag(), m.key, messageImprint)
	if merr != nil {
		return nil, fmt.Errorf("tsa: MAC 计算失败: %w", merr)
	}
	// TSAPublicKey = 密钥指纹（Hash(key)），**仅供标识，绝不暴露密钥字节**。
	// 修复 F-9/U-7：原式 `sha256.New().Sum(append([]byte(nil), m.key...))[:16]` 的 Sum 语义为
	// "把当前（空输入的）摘要附加到入参之后"，故其返回值前 16 字节 = HMAC key 的前 16 字节，
	// 直接把密钥写进公开 TST —— 属泄密缺陷。
	fp, _ := hashByAlg(hashAlgTag(), m.key)
	return &TST{
		Version:        1,
		Algorithm:      tstAlgorithm(),
		TimestampNS:    time.Now().UnixNano(),
		MessageImprint: hex.EncodeToString(messageImprint),
		Signature:      hex.EncodeToString(mac),
		TSAPublicKey:   hex.EncodeToString(fp),
		Source:         "mock",
	}, nil
}

// Verify 验证 TST。算法按 §5.2.2 判定口径分派：**仅** `Algorithm=="sm3"` 判 SM3；
// 空/其它值一律按 SHA-256（fail-safe 默认，防伪造字段绕过）；未知算法必然导致 MAC 不符而拒绝。
func (m *MockTSA) Verify(t *TST) error {
	if t == nil {
		return errors.New("tsa: 空 TST")
	}
	if t.Version != 1 {
		return errors.New("tsa: 版本不支持")
	}
	imprint, err := hex.DecodeString(t.MessageImprint)
	if err != nil {
		return errors.New("tsa: message_imprint 非 hex")
	}
	alg := ""
	if t.Algorithm == "sm3" {
		alg = "sm3"
	}
	mac, merr := hmacByAlg(alg, m.key, imprint)
	if merr != nil {
		return errors.New("tsa: TST 签名无效（时间戳被篡改）")
	}
	got, _ := hex.DecodeString(t.Signature)
	if subtle.ConstantTimeCompare(got, mac) != 1 {
		return errors.New("tsa: TST 签名无效（时间戳被篡改）")
	}
	return nil
}

// ---------- HTTPTSA（RFC 3161 外部 TSA，生产路径） ----------

// HTTPTSA 对接外部 RFC 3161 TSA 服务（D-8：外部 TSA 真实实现）。
//
// 协议：HTTP POST，Content-Type: application/timestamp-query，body=ASN.1 DER TimeStampReq
// 响应：Content-Type: application/timestamp-reply，body=ASN.1 DER TimeStampResp
//
// 零新增依赖：
//   - ASN.1 编解码用 encoding/asn1（stdlib）
//   - PKCS#7 签名验证用 gmsm/pkcs7（项目既有依赖）
//   - 证书池用 smx509（gmsm 内置，兼容标准 x509 + SM2）
//
// fail-closed：
//   - TSA 不可达 / 网络超时 → 报错
//   - 状态非 granted → 报错
//   - PKCS#7 签名无效 → 报错
//   - messageImprint 不匹配 → 报错
//   - 证书链验证失败 → 报错
type HTTPTSA struct {
	endpoint    string            // TSA 服务 URL
	rootCerts   *smx509.CertPool  // 可信根证书池（用于验证 TST 签名）
	timeout     time.Duration     // HTTP 超时
	policyOID   asn1.ObjectIdentifier // 请求的 TSA 策略（可选）
}

// HTTPTSAOption HTTPTSA 构造选项。
type HTTPTSAOption func(*HTTPTSA)

// WithTSATimeout 设置 HTTP 超时时间。
func WithTSATimeout(d time.Duration) HTTPTSAOption {
	return func(h *HTTPTSA) { h.timeout = d }
}

// WithTSAPolicy 设置请求的 TSA 策略 OID。
func WithTSAPolicy(oid asn1.ObjectIdentifier) HTTPTSAOption {
	return func(h *HTTPTSA) { h.policyOID = oid }
}

// NewHTTPTSA 构造外部 TSA 客户端。
//
// endpoint: TSA 服务 URL（如 "https://timestamp.digicert.com"）
// rootCertsPEM: 可信根证书 PEM（可为空，此时用系统根证书）
// fail-closed：endpoint 为空 → 报错。
func NewHTTPTSA(endpoint string, rootCertsPEM []byte, opts ...HTTPTSAOption) (*HTTPTSA, error) {
	if endpoint == "" {
		return nil, errors.New("tsa: endpoint 不能为空")
	}
	h := &HTTPTSA{
		endpoint: endpoint,
		timeout:  10 * time.Second,
	}
	for _, opt := range opts {
		opt(h)
	}

	// 初始化根证书池
	if len(rootCertsPEM) > 0 {
		pool := smx509.NewCertPool()
		if !pool.AppendCertsFromPEM(rootCertsPEM) {
			return nil, errors.New("tsa: 根证书 PEM 解析失败")
		}
		h.rootCerts = pool
	} else {
		// 无显式根证书 → 用系统根证书池（fail-safe，生产环境建议显式配置）
		systemPool, err := smx509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("tsa: 获取系统根证书池失败: %w", err)
		}
		h.rootCerts = systemPool
	}

	return h, nil
}

// Sign 向外部 TSA 请求时间戳（实现 TSASigner 接口）。
//
// messageImprint: 待时间戳的消息摘要（32B SHA-256 或 32B SM3）
// 返回内部 TST 结构（JSON 兼容 MockTSA），其中：
//   - Signature = PKCS#7 SignedData DER 的 hex 编码（完整 TST，可独立验证）
//   - TSAPublicKey = 签名证书序列号 hex（标识用，非密钥）
func (h *HTTPTSA) Sign(messageImprint []byte) (*TST, error) {
	if len(messageImprint) == 0 {
		return nil, errors.New("tsa: message_imprint 为空")
	}

	// 1. 构造 TimeStampReq
	req, err := h.buildRequest(messageImprint)
	if err != nil {
		return nil, fmt.Errorf("tsa: 构造请求失败: %w", err)
	}

	// 2. HTTP POST
	respBody, err := h.doRequest(req)
	if err != nil {
		return nil, fmt.Errorf("tsa: 请求失败: %w", err)
	}

	// 3. 解析 TimeStampResp
	tsResp, err := parseTimeStampResp(respBody)
	if err != nil {
		return nil, fmt.Errorf("tsa: 解析响应失败: %w", err)
	}

	// 4. 检查 PKIStatus（granted=0 或 grantedWithMods=1）
	if tsResp.Status.Status != 0 && tsResp.Status.Status != 1 {
		reason := ""
		if len(tsResp.Status.StatusString) > 0 {
			reason = tsResp.Status.StatusString[0]
		}
		return nil, fmt.Errorf("tsa: 拒绝签发（status=%d, reason=%s）", tsResp.Status.Status, reason)
	}

	// 5. TST 签名验证（用根证书池）
	if tsResp.TimeStampToken == nil {
		return nil, errors.New("tsa: 响应缺失 timeStampToken")
	}
	tstInfo, signerCert, err := verifyTSTToken(tsResp.TimeStampToken, messageImprint, h.rootCerts)
	if err != nil {
		return nil, fmt.Errorf("tsa: TST 验证失败: %w", err)
	}

	// 6. 映射为内部 TST 结构
	// Signature = 完整 PKCS#7 DER（便于独立验签）
	// TSAPublicKey = 签名证书序列号（标识用）
	sigHex := hex.EncodeToString(tsResp.TimeStampToken)
	serialHex := hex.EncodeToString(signerCert.SerialNumber.Bytes())

	return &TST{
		Version:        1,
		Algorithm:      tstAlgorithm(),
		TimestampNS:    tstInfo.GenTime.UnixNano(),
		MessageImprint: hex.EncodeToString(messageImprint),
		Signature:      sigHex,
		TSAPublicKey:   serialHex,
		Source:         "http_rfc3161",
	}, nil
}

// Verify 验证 TST（实现 TSASigner 接口）。
//
// 对 HTTPTSA 来说，验签需要根证书池和原始 messageImprint。
// 由于 TSASigner.Verify 接口签名只传 TST，不传 messageImprint，
// 这里只做 TST 结构完整性和签名证书链验证（不验 messageImprint）。
// 完整验签用 VerifyTSTIndependent。
func (h *HTTPTSA) Verify(t *TST) error {
	if t == nil {
		return errors.New("tsa: 空 TST")
	}
	if t.Source != "http_rfc3161" {
		return fmt.Errorf("tsa: source=%s 不是 RFC3161 TST", t.Source)
	}
	sigBytes, err := hex.DecodeString(t.Signature)
	if err != nil {
		return errors.New("tsa: signature 非 hex")
	}
	// 只验签名链和证书有效性，不验 messageImprint（接口限制）
	p7, err := pkcs7.Parse(sigBytes)
	if err != nil {
		return fmt.Errorf("tsa: 解析 PKCS#7 失败: %w", err)
	}
	if err := p7.VerifyWithChain(h.rootCerts); err != nil {
		return fmt.Errorf("tsa: PKCS#7 签名无效: %w", err)
	}
	return nil
}

// VerifyTSTIndependent 独立验证 TST（不依赖 HTTPTSA 实例）。
//
// 参数：
//   - t: 内部 TST 结构
//   - messageImprint: 原始消息摘要
//   - rootCertsPEM: 可信根证书 PEM（可为空=系统根）
//
// 用途：离线审计、跨实例 TST 验证、归档后验签。
// fail-closed：任一步失败 → 报错。
func VerifyTSTIndependent(t *TST, messageImprint []byte, rootCertsPEM []byte) error {
	if t == nil {
		return errors.New("tsa: 空 TST")
	}
	if t.Source != "http_rfc3161" {
		return fmt.Errorf("tsa: source=%s 不是 RFC3161 TST", t.Source)
	}

	// 解析根证书
	var pool *smx509.CertPool
	if len(rootCertsPEM) > 0 {
		pool = smx509.NewCertPool()
		if !pool.AppendCertsFromPEM(rootCertsPEM) {
			return errors.New("tsa: 根证书 PEM 解析失败")
		}
	} else {
		systemPool, err := smx509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("tsa: 获取系统根证书池失败: %w", err)
		}
		pool = systemPool
	}

	sigBytes, err := hex.DecodeString(t.Signature)
	if err != nil {
		return errors.New("tsa: signature 非 hex")
	}

	_, _, err = verifyTSTToken(sigBytes, messageImprint, pool)
	return err
}

// ---- RFC 3161 ASN.1 结构 ----

// 算法 OID
var (
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSM3    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}
)

// algorithmIdentifier AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY DEFINED BY algorithm OPTIONAL }
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// tstMessageImprint MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
type tstMessageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

// timeStampReq TimeStampReq ::= SEQUENCE { version INTEGER, reqPolicy TSAPolicyId OPTIONAL, messageImprint MessageImprint, nonce INTEGER OPTIONAL, certReq BOOLEAN DEFAULT FALSE }
type timeStampReq struct {
	Version        int
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	MessageImprint tstMessageImprint
	Nonce          *big.Int `asn1:"optional"`
	CertReq        bool     `asn1:"optional"`
}

// pkiStatusInfo PKIStatusInfo ::= SEQUENCE { status PKIStatus, statusString PKIFreeText OPTIONAL, failInfo PKIFailureInfo OPTIONAL }
type pkiStatusInfo struct {
	Status       int
	StatusString []string `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// timeStampResp TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TimeStampToken OPTIONAL }
// TimeStampToken ::= ContentInfo -- 即 PKCS#7 结构
type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken []byte `asn1:"optional,tag:0"`
}

// tstInfo TSTInfo ::= SEQUENCE { version INTEGER, policy TSAPolicyId, messageImprint MessageImprint, serialNumber INTEGER, genTime GeneralizedTime, accuracy Accuracy OPTIONAL, ordering BOOLEAN DEFAULT FALSE, nonce INTEGER OPTIONAL, tsa [0] GeneralName OPTIONAL, extensions [1] IMPLICIT Extensions OPTIONAL }
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint tstMessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
	// 后续字段可选，简化实现不解析
	Rest asn1.RawValue `asn1:"optional"`
}

// buildRequest 构造 RFC 3161 TimeStampReq DER。
func (h *HTTPTSA) buildRequest(messageImprint []byte) ([]byte, error) {
	// 选择哈希算法 OID
	var algOID asn1.ObjectIdentifier
	if cryptoProvider.Profile() == cryptop.ProfileIntl {
		algOID = oidSHA256
	} else {
		algOID = oidSM3
	}

	req := timeStampReq{
		Version: 1,
		MessageImprint: tstMessageImprint{
			HashAlgorithm: algorithmIdentifier{
				Algorithm: algOID,
				// SHA-256/SM3 参数可为 NULL 或缺省，此处省略（用 optional tag）
			},
			HashedMessage: messageImprint,
		},
		CertReq: true, // 请求 TSA 在响应中包含证书
	}
	if h.policyOID != nil {
		req.ReqPolicy = h.policyOID
	}

	return asn1.Marshal(req)
}

// doRequest 发送 HTTP 请求。
func (h *HTTPTSA) doRequest(reqBody []byte) ([]byte, error) {
	client := &http.Client{Timeout: h.timeout}
	req, err := http.NewRequest("POST", h.endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	req.Header.Set("Accept", "application/timestamp-reply")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tsa: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // 限制 64KB
	if err != nil {
		return nil, err
	}
	return body, nil
}

// parseTimeStampResp 解析 TimeStampResp DER。
func parseTimeStampResp(data []byte) (*timeStampResp, error) {
	var resp timeStampResp
	rest, err := asn1.Unmarshal(data, &resp)
	if err != nil {
		return nil, fmt.Errorf("解析 TimeStampResp 失败: %w", err)
	}
	if len(rest) > 0 {
		return nil, errors.New("TimeStampResp 有多余字节")
	}
	return &resp, nil
}

// verifyTSTToken 验证 PKCS#7 TimeStampToken 签名 + messageImprint。
// 返回：解析后的 TSTInfo、签名证书、错误。
func verifyTSTToken(tstDER []byte, expectedImprint []byte, roots *smx509.CertPool) (*tstInfo, *smx509.Certificate, error) {
	// 1. 解析 PKCS#7
	p7, err := pkcs7.Parse(tstDER)
	if err != nil {
		return nil, nil, fmt.Errorf("解析 PKCS#7 失败: %w", err)
	}

	// 2. 验证签名链
	if err := p7.VerifyWithChain(roots); err != nil {
		return nil, nil, fmt.Errorf("PKCS#7 签名验证失败: %w", err)
	}

	// 3. 提取签名证书
	signerCert := p7.GetOnlySigner()
	if signerCert == nil {
		return nil, nil, errors.New("PKCS#7 中无签名者证书")
	}

	// 4. 解析 TSTInfo（PKCS#7 content 即 TSTInfo DER）
	var tst tstInfo
	if _, err := asn1.Unmarshal(p7.Content, &tst); err != nil {
		return nil, nil, fmt.Errorf("解析 TSTInfo 失败: %w", err)
	}

	// 5. 校验 messageImprint
	if len(tst.MessageImprint.HashedMessage) != len(expectedImprint) {
		return nil, nil, fmt.Errorf("messageImprint 长度不符: got %d, want %d",
			len(tst.MessageImprint.HashedMessage), len(expectedImprint))
	}
	if subtle.ConstantTimeCompare(tst.MessageImprint.HashedMessage, expectedImprint) != 1 {
		return nil, nil, errors.New("messageImprint 不匹配")
	}

	return &tst, signerCert, nil
}

// ---------- 兼容性说明 ----------
//
// D-T6-1（研发日志）：HTTPTSA 使用 gmsm/pkcs7 做 PKCS#7 验证，
// 而 gmsm/pkcs7 内部用 smx509。smx509 是 stdlib x509 的超集（SM2/SM3/SM4 扩展），
// 兼容 RSA/ECDSA 标准证书，因此可用于验证主流公共 TSA（DigiCert/GlobalSign 等）。
// 风险：若某 TSA 使用了 smx509 不支持的算法，将验签失败。
// 缓解：生产环境接入前先做联通性验证；必要时添加 stdlib crypto/x509 备选路径。
//
// D-T6-2：TSASigner.Verify 接口签名不接收 messageImprint，
// HTTPTSA.Verify 只做证书链验证，不做 messageImprint 校验。
// 完整验签（含 messageImprint）用 VerifyTSTIndependent。
// 依据：TSASigner 接口是既有定义，修改接口会影响 MockTSA 及所有调用点（侵入过大）。
// 影响范围：HTTPTSA.Verify 的调用方需注意只验证书链，不算完整验签。
// 完整验签统一走 VerifyTSTIndependent（审计/对账等下游路径）。

func marshalTST(t *TST) ([]byte, error) {
	return json.Marshal(t)
}

func unmarshalTST(data []byte) (*TST, error) {
	var t TST
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	return &t, nil
}
