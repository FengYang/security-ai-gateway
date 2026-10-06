// Package auditverify — 审计链独立验证器（Phase 2 门禁 #4「审计链工具验证通过」）。
//
// 定位：与运行中的服务**完全独立**的实现——不 import 服务端代码、不调用服务端点，
// 由第三方（或流水线）拿到链文件 / 导出 NDJSON（可选带锚点文件）即可自行重算哈希链
// 并判定「是否被篡改」与「是否被截断」。与 gateway/attest-verify（D2：证明验证出插件）
// 同一设计理念：让校验能力脱离被校验对象。
//
// ⚠️ 硬约束（防双实现漂移）：本包的字段序与编码必须与两端 hash() 逐字段一致——
//   - admin 链：gateway/gateway-admin-service/audit.go  adminAuditEvent.hash()
//   - tee 链  ：gateway/tee-infer-service/audit.go       AuditEvent.hash()
//
// 任一端改动字段/顺序/编码，必须同步本文件与 verifier_test.go 的固定测试向量
// （向量由独立实现算出，见测试注释），否则验证器会误报"链断裂"——比没有验证器更危险。
package auditverify

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"security-ai-gateway/gateway/cryptop"
)

// ---- 算法分派（P0-4 §5.2.2 / R-12 / R-13）----
//
// 与进程 profile **解耦**：验证器须能同时复算 SHA-256（缺省）与 SM3 事件（混合链，T-5.2-3）。
var (
	hashProvSHA256 = mustProv(cryptop.ProfileIntl)
	hashProvSM3    = mustProv(cryptop.ProfileSMSW)
)

func mustProv(p cryptop.Profile) cryptop.Provider {
	prov, err := cryptop.New(p)
	if err != nil {
		panic("audit-verify: 初始化 " + string(p) + " provider 失败: " + err.Error())
	}
	return prov
}

// hashAlgOf 取事件自述 `hash_alg` 并做 R-12/R-13 判定：
//   - 缺失/空 → SHA-256（R-13，唯一允许的缺省）；
//   - "sm3"   → SM3；
//   - 其它任何值（含拼写错误的 "sha256"）→ **错误**（R-12：验证失败，绝不静默回退）。
func hashAlgOf(event map[string]any) (string, error) {
	raw, ok := event["hash_alg"]
	if !ok || raw == nil {
		return "", nil
	}
	s, isStr := raw.(string)
	if !isStr {
		return "", fmt.Errorf("hash_alg 类型不支持：%T（应为 string）", raw)
	}
	switch s {
	case "":
		return "", nil
	case "sm3":
		return "sm3", nil
	default:
		return "", fmt.Errorf("未知 hash_alg %q（R-12：验证失败，不得静默回退 SHA-256）", s)
	}
}

// Field 哈希输入字段。
type Field struct {
	JSONKey     string
	IsNumber    bool   // 数值字段：取 JSON 字面量（json.Number）十进制文本
	SkipIfEmpty bool   // 条件编码：值为空串时**不进哈希**（admin 链的 Target）
	DefaultZero string // 字段缺省时的取值（数值字段为 "0"）
}

// Schema 一套链的哈希编码规则（字段序敏感）。
type Schema struct {
	Name   string
	Fields []Field
}

// Schemas 受支持的链。
var Schemas = map[string]Schema{
	// 管理面链（gateway-admin-service）：Target 为空时不进哈希（M3-A 引入时的向后兼容设计）。
	"admin": {
		Name: "admin",
		Fields: []Field{
			{JSONKey: "event_id"},
			{JSONKey: "timestamp", IsNumber: true, DefaultZero: "0"},
			{JSONKey: "actor"},
			{JSONKey: "action"},
			{JSONKey: "provider"},
			{JSONKey: "key_fingerprint"},
			{JSONKey: "tenant"},
			{JSONKey: "max_tokens", IsNumber: true, DefaultZero: "0"},
			{JSONKey: "target", SkipIfEmpty: true},
			{JSONKey: "request_id"},
			{JSONKey: "result"},
		},
	},
	// 数据面链（tee-infer-service）：另有若干证据字段（transformed_hash/cache_hit/key_fp/
	// metering_mode/engine_type/model）**不进哈希**，故不在此列出。
	"tee": {
		Name: "tee",
		Fields: []Field{
			{JSONKey: "event_id"},
			{JSONKey: "timestamp", IsNumber: true, DefaultZero: "0"},
			{JSONKey: "tenant_id"},
			{JSONKey: "user_id"},
			{JSONKey: "request_id"},
			{JSONKey: "action"},
			{JSONKey: "tokens_in", IsNumber: true, DefaultZero: "0"},
			{JSONKey: "tokens_out", IsNumber: true, DefaultZero: "0"},
			{JSONKey: "result"},
			{JSONKey: "payload_hash"},
		},
	},
	// 控制面策略变更链（gateway-core）：gateway/gateway-core/internal/policyaudit 的 Event.hash()。
	// 说明：字段为空串时**仍进哈希**（与 admin 链的 Target 不同），故此处不设 SkipIfEmpty。
	"core": {
		Name: "core",
		Fields: []Field{
			{JSONKey: "event_id"},
			{JSONKey: "timestamp", IsNumber: true, DefaultZero: "0"},
			{JSONKey: "actor"},
			{JSONKey: "action"},
			{JSONKey: "version_from", IsNumber: true, DefaultZero: "0"},
			{JSONKey: "version_to", IsNumber: true, DefaultZero: "0"},
			{JSONKey: "rule_id"},
			{JSONKey: "change"},
			{JSONKey: "field"},
			{JSONKey: "old_value"},
			{JSONKey: "new_value"},
			{JSONKey: "request_id"},
			{JSONKey: "result"},
		},
	},
}

// SchemaFor 按名称取 schema。
func SchemaFor(name string) (Schema, error) {
	s, ok := Schemas[name]
	if !ok {
		return Schema{}, fmt.Errorf("未知 schema %q（支持：admin / tee / core）", name)
	}
	return s, nil
}

// Hash 重算单条事件的哈希（与两端 hash() 同构：8 字节大端长度前缀 + 字段字节）。
// 算法由事件自述 `hash_alg` 分派（R-12/R-13）；**长度前缀与字段序逐字节不变** ⇒ 旧链哈希恒定。
// 事件字段从 JSON 解码而来，故数值字段用 json.Number 保留字面量，避免 float64 精度丢失
// （如纳秒时间戳 1700000000000000000 转 float64 会失真）。
func (s Schema) Hash(event map[string]any) (string, error) {
	alg, err := hashAlgOf(event)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	for _, f := range s.Fields {
		str, err := fieldText(event, f)
		if err != nil {
			return "", err
		}
		if f.SkipIfEmpty && str == "" {
			continue
		}
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(str)))
		buf.Write(l[:])
		buf.WriteString(str)
	}
	prov := hashProvSHA256
	if alg == "sm3" {
		prov = hashProvSM3
	}
	return hex.EncodeToString(prov.Hash(buf.Bytes())), nil
}

// fieldText 取字段文本（缺省 → 数值 "0"，字符串 ""）。
func fieldText(event map[string]any, f Field) (string, error) {
	raw, ok := event[f.JSONKey]
	if !ok || raw == nil {
		if f.IsNumber {
			return f.DefaultZero, nil
		}
		return "", nil
	}
	switch v := raw.(type) {
	case string:
		return v, nil
	case json.Number:
		return v.String(), nil
	case bool:
		return strconv.FormatBool(v), nil
	default:
		return "", fmt.Errorf("字段 %s 类型不支持：%T（数值应为 json.Number，需 UseNumber 解码）", f.JSONKey, raw)
	}
}
