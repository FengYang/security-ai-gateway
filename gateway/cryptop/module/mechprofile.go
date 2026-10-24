// mechprofile.go —— 厂商机制 profile 常量表（B-6.1-2）。
//
// 背景与硬约束：
//   - PKCS#11 v3.0 标准**未定义 SM 机制的 CKM 常量**——SM 支持属厂商扩展
//     （如 IBM 用 0x8005xxxx 私有段）。因此"机制名 → CKM 值"的映射必须
//     **逐厂商按厂商 SDK 文档以 profile 文件登记**，禁止按"标准值"臆测；
//   - 代码侧 Capabilities 只登记**探测命中**的机制（R-S3-11/B-6.1-6），
//     profile 表仅是 CKM → 机制名的翻译依据，不构成能力宣称；
//   - "不得把 AES 等标准机制映射成 SM 名冒充合规"（S3-a 选型基线 §5.1）：
//     校验规则强制 SM 条目的 source 必须标注厂商文档来源（含 "vendor"），
//     standard-header 不构成 SM 登记依据。
//
// profile 文件格式（JSON，每厂商一份，随 SDK 文档登记）：
//
//	{
//	  "profile_id": "vendor-x-pkcs11",
//	  "vendor": "vendor-x",
//	  "interface": "pkcs11",            // 当前仅支持 pkcs11（SDF 随 sdf.go 接入后扩展）
//	  "description": "...",
//	  "mechanisms": [
//	    {"name":"sm4-gcm","ckm":"0x80050001","sm":true,
//	     "source":"vendor-doc:X-HSM-SDK-v3.2 §5.1","note":"必须支持 GCM"}
//	  ]
//	}
//
// CKM 值接受 "0x" 前缀十六进制或十进制字符串；厂商私有段（0x8005xxxx 等）
// 用十六进制表达最清晰。
package cryptopmodule

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// MechEntry profile 中单条机制登记。
type MechEntry struct {
	Name       string `json:"name"`         // 稳定机制名（须在 IsKnownMechanism 全集内）
	CKM        string `json:"ckm"`          // CKM 值（"0x..." 十六进制或十进制字符串）
	SM         bool   `json:"sm"`           // 是否国密机制（SM 条目 source 必须含 vendor）
	MinKeyBits int    `json:"min_key_bits"` // 密钥长度下限（bit；0=不适用/不限）
	MaxKeyBits int    `json:"max_key_bits"` // 密钥长度上限（bit；0=不适用/不限）
	Source     string `json:"source"`       // 登记来源（vendor-doc:... / standard-header:...）
	Note       string `json:"note,omitempty"`
}

// MechProfile 厂商机制 profile 文件（每厂商一份，随 SDK 文档登记）。
type MechProfile struct {
	ProfileID   string      `json:"profile_id"`
	Vendor      string      `json:"vendor"`
	Interface   string      `json:"interface"`
	Description string      `json:"description"`
	Mechanisms  []MechEntry `json:"mechanisms"`
}

// mechInterfacePKCS11 当前唯一支持的 profile 接口类型。
// SDF（GM/T 0018）profile 随 sdf.go 接入后启用（S3-a 采购厂商 SDK）。
const mechInterfacePKCS11 = "pkcs11"

// LoadMechProfile 从文件加载并校验厂商机制 profile（fail-closed：
// 任一不合规即返回明确错误，由 Config.Validate / Init 拒绝启动）。
func LoadMechProfile(path string) (*MechProfile, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("module_mechanism_profile: 路径为空")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("module_mechanism_profile %s 不可读: %w", path, err)
	}
	var p MechProfile
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("module_mechanism_profile %s 解析失败（须为 JSON）: %w", path, err)
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("module_mechanism_profile %s 校验失败: %w", path, err)
	}
	return &p, nil
}

// validate profile 静态校验（§7.4/B-6.1-2；全部 fail-closed）。
func (p *MechProfile) validate() error {
	if strings.TrimSpace(p.ProfileID) == "" {
		return fmt.Errorf("profile_id 为空")
	}
	if strings.TrimSpace(p.Vendor) == "" {
		return fmt.Errorf("vendor 为空")
	}
	if p.Interface != mechInterfacePKCS11 {
		return fmt.Errorf("interface=%q 不支持（当前仅 %q；SDF profile 随 sdf.go 接入后启用）",
			p.Interface, mechInterfacePKCS11)
	}
	if len(p.Mechanisms) == 0 {
		return fmt.Errorf("mechanisms 为空（至少登记一条机制）")
	}
	seenName := make(map[string]bool, len(p.Mechanisms))
	seenCKM := make(map[uint]string, len(p.Mechanisms))
	for i, e := range p.Mechanisms {
		if strings.TrimSpace(e.Name) == "" {
			return fmt.Errorf("mechanisms[%d]: name 为空", i)
		}
		if !IsKnownMechanism(e.Name) {
			return fmt.Errorf("mechanisms[%d]: 未知机制名 %q（须在机制名全集内；SM 名只能来自厂商 profile）", i, e.Name)
		}
		if seenName[e.Name] {
			return fmt.Errorf("mechanisms[%d]: 机制名 %q 重复登记", i, e.Name)
		}
		seenName[e.Name] = true

		v, err := parseCKM(e.CKM)
		if err != nil {
			return fmt.Errorf("mechanisms[%d] (%s): %w", i, e.Name, err)
		}
		if v == 0 {
			return fmt.Errorf("mechanisms[%d] (%s): CKM 为 0（厂商 profile 须按 SDK 文档填写，禁止臆测标准值）", i, e.Name)
		}
		if prev, ok := seenCKM[v]; ok {
			return fmt.Errorf("mechanisms[%d] (%s): CKM %s 与机制 %q 冲突（同一 CKM 不得映射两个机制名）",
				i, e.Name, formatCKM(v), prev)
		}
		seenCKM[v] = e.Name

		if strings.TrimSpace(e.Source) == "" {
			return fmt.Errorf("mechanisms[%d] (%s): source 为空（须标注登记来源）", i, e.Name)
		}
		if e.SM && !strings.Contains(strings.ToLower(e.Source), "vendor") {
			return fmt.Errorf("mechanisms[%d] (%s): SM 机制的 source 必须标注厂商文档来源（含 \"vendor\"，如 vendor-doc:<SDK 版本> §x.y）；standard-header 不构成 SM 机制登记依据",
				i, e.Name)
		}
		if e.MinKeyBits < 0 || e.MaxKeyBits < 0 {
			return fmt.Errorf("mechanisms[%d] (%s): 密钥长度不得为负（min=%d max=%d）",
				i, e.Name, e.MinKeyBits, e.MaxKeyBits)
		}
		if e.MinKeyBits > 0 && e.MaxKeyBits > 0 && e.MinKeyBits > e.MaxKeyBits {
			return fmt.Errorf("mechanisms[%d] (%s): min_key_bits(%d) > max_key_bits(%d)",
				i, e.Name, e.MinKeyBits, e.MaxKeyBits)
		}
	}
	return nil
}

// parseCKM 解析 CKM 值：接受 "0x"/"0X" 前缀十六进制或十进制字符串。
func parseCKM(s string) (uint, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, fmt.Errorf("CKM 未登记（ckm 为空；厂商 profile 须按 SDK 文档填写，禁止臆测标准值）")
	}
	if strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "0X") {
		v, err := strconv.ParseUint(t[2:], 16, 64)
		if err != nil {
			return 0, fmt.Errorf("CKM %q 非法十六进制: %v", s, err)
		}
		return uint(v), nil
	}
	v, err := strconv.ParseUint(t, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("CKM %q 非法（须 0x 前缀十六进制或十进制）: %v", s, err)
	}
	return uint(v), nil
}

// formatCKM 规范化 CKM 显示（日志/错误消息）。
func formatCKM(v uint) string { return fmt.Sprintf("0x%08x", v) }

// MechTable 解析后的机制表（profile 的运行形态）：name→条目、CKM→name。
type MechTable struct {
	ProfileID string
	byName    map[string]MechEntry
	byCKM     map[uint]string
}

// Table 将校验通过的 profile 转为运行表。
func (p *MechProfile) Table() *MechTable {
	t := &MechTable{
		ProfileID: p.ProfileID,
		byName:    make(map[string]MechEntry, len(p.Mechanisms)),
		byCKM:     make(map[uint]string, len(p.Mechanisms)),
	}
	for _, e := range p.Mechanisms {
		v, err := parseCKM(e.CKM)
		if err != nil || v == 0 {
			continue // validate 已保证可达；防御性跳过
		}
		e.CKM = formatCKM(v) // 规范化
		t.byName[e.Name] = e
		t.byCKM[v] = e.Name
	}
	return t
}

// EmptyMechTable 空表（未配置 profile：仅 rand 恒登记，无厂商机制）。
func EmptyMechTable() *MechTable {
	return &MechTable{byName: map[string]MechEntry{}, byCKM: map[uint]string{}}
}

// Lookup 按机制名取条目。
func (t *MechTable) Lookup(name string) (MechEntry, bool) {
	if t == nil {
		return MechEntry{}, false
	}
	e, ok := t.byName[name]
	return e, ok
}

// NameByCKM 按 CKM 值取机制名（探测命中翻译用）。
func (t *MechTable) NameByCKM(ckm uint) (string, bool) {
	if t == nil {
		return "", false
	}
	n, ok := t.byCKM[ckm]
	return n, ok
}

// Names 已登记机制名（升序）。
func (t *MechTable) Names() []string {
	if t == nil {
		return nil
	}
	out := make([]string, 0, len(t.byName))
	for n := range t.byName {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Len 登记条数。
func (t *MechTable) Len() int {
	if t == nil {
		return 0
	}
	return len(t.byName)
}

// IsEmpty 是否未登记任何机制。
func (t *MechTable) IsEmpty() bool { return t.Len() == 0 }
