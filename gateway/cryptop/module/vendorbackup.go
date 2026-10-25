package cryptopmodule

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
)

// 厂商专有备份机制的能力抽象与探测（D-2 / U-2 / U-7 / §15.3 MUST-4）。
//
// 背景（真机实测结论）：PKCS#11 规范规定 CKA_EXTRACTABLE=false 的密钥不能被
// C_WrapKey（SoftHSM 返回 CKR_KEY_UNEXTRACTABLE），而 R-2 要求生产密钥一律
// 不可导出 ⇒ **标准 wrap 路径备份不了生产密钥**，真实备份必须走厂商专有机制。
//
// 设计原则：**厂商机制通过配置接入，代码零改动**。
//   - 厂商在 module_mechanism_profile 中登记专有机制名（约定见下）；
//   - 本文件据机制表探测能力，供组模式启动时决定 shared 是否成立；
//   - 探测不到任何备份机制 → shared 不得启动（fail-closed），只能 isolated。
//
// 约定的厂商机制名（profile 未登记即视为不支持，B-6.1-2 一律 fail-closed，
// 禁止臆测标准 CKM 值）：
const (
	// MechVendorBackupWrap 厂商专有 wrap：把不可导出密钥包成备份 blob
	// （HSM backup token / 厂商备份库路径）。
	MechVendorBackupWrap = "vendor-backup-wrap"
	// MechVendorClone 克隆域：同域设备间克隆密钥对象。
	MechVendorClone = "vendor-clone"
	// MechVendorBackupLib 厂商备份库客户端（§6.2.5 backup.endpoint mTLS）。
	MechVendorBackupLib = "vendor-backup-lib"
	// MechVendorMofN 厂商 m-of-n 拆分/重组（U-7）。
	MechVendorMofN = "vendor-mofn"
)

// BackupMechanismKind 厂商备份机制种类（MUST-4 核验结果决定 D-20 架构分叉）。
type BackupMechanismKind string

const (
	// BackupMechNone 无任何备份机制 ⇒ key_mode 只能 isolated（不宣称 G-4）。
	BackupMechNone BackupMechanismKind = "none"
	// BackupMechVendorWrap 厂商专有 wrap（备份 token / 备份库）。
	BackupMechVendorWrap BackupMechanismKind = "vendor_wrap"
	// BackupMechVendorClone 克隆域。
	BackupMechVendorClone BackupMechanismKind = "vendor_clone"
	// BackupMechVendorLib 厂商备份库。
	BackupMechVendorLib BackupMechanismKind = "vendor_lib"
	// BackupMechMofN m-of-n（U-7）。
	BackupMechMofN BackupMechanismKind = "mofn"
)

// VendorBackupCaps 厂商备份能力探测结果。
//
// Note 供审计/日志说明判定依据；Supported=false 时 Kind 恒为 BackupMechNone。
type VendorBackupCaps struct {
	Kind      BackupMechanismKind
	MechName  string // profile 登记的机制名
	Supported bool
	Note      string
}

// ProbeVendorBackup 从机制表探测厂商备份能力（启动时调用一次）。
//
// 优先级：vendor-backup-wrap > vendor-clone > vendor-backup-lib > mofn。
// 多个同时登记时取第一个，其余记入 Note（便于运维知道还有未用的能力）。
func ProbeVendorBackup(t *MechTable) VendorBackupCaps {
	none := func(note string) VendorBackupCaps {
		return VendorBackupCaps{Kind: BackupMechNone, Supported: false, Note: note}
	}
	if t == nil || t.IsEmpty() {
		return none("未配置机制 profile（B-6.1-2：无 CKM 登记，视为无备份能力）")
	}

	order := []struct {
		name string
		kind BackupMechanismKind
	}{
		{MechVendorBackupWrap, BackupMechVendorWrap},
		{MechVendorClone, BackupMechVendorClone},
		{MechVendorBackupLib, BackupMechVendorLib},
		{MechVendorMofN, BackupMechMofN},
	}
	var extra []string
	for _, c := range order {
		if _, ok := t.Lookup(c.name); ok {
			note := "profile 登记 " + c.name
			if len(extra) > 0 {
				note += "（另有未使用能力：" + strings.Join(extra, ",") + "）"
			}
			return VendorBackupCaps{Kind: c.kind, MechName: c.name, Supported: true, Note: note}
		}
		extra = append(extra, c.name)
	}
	return none("profile 未登记任何厂商备份机制（" + strings.Join(extra, ",") + "）⇒ shared 不得启动，只能 isolated")
}

// MofNBackend 厂商 m-of-n 备份能力（U-7：厂商可选）。
//
// 不支持时按 U-7 用「双签 + 备份库加密」替代，并登记"不支持 m-of-n"——
// **双签不等于密码学 m-of-n**（前者是流程控制，后者是密码学门限）。
type MofNBackend interface {
	// Split 把秘密拆成 n 份份额，任取 k 份可恢复。
	Split(secret []byte, n, k int) ([][]byte, error)
	// Combine 用份额恢复秘密（份额数 < k 必须失败）。
	Combine(shares [][]byte) ([]byte, error)
}

// ErrMofNUnsupported 厂商不支持 m-of-n（U-7：须登记"不支持"，不得冒充）。
var ErrMofNUnsupported = errors.New("cryptopmodule: vendor_mofn_unsupported")

// SoftwareMofN 软件 m-of-n 兜底实现（**仅用于无厂商机制时的降级路径**）。
//
// 口径（U-7）：它是"双签 + 份额拆分"的工程替代，**不是密码学 m-of-n**——
// 份额在本进程内拆分/重组，无法防止单点 compromisation。使用它必须同时在
// 材料中登记"不支持密码学 m-of-n"。
type SoftwareMofN struct{}

// Split 用 XOR 份额做 (k=n) 门限拆分：任一份额丢失即不可恢复，满足"全部在场"语义。
func (SoftwareMofN) Split(secret []byte, n, k int) ([][]byte, error) {
	if n < 2 || k < 2 || k > n {
		return nil, fmt.Errorf("mofn: 参数非法（n=%d k=%d，要求 n>=2 且 2<=k<=n）", n, k)
	}
	if len(secret) == 0 {
		return nil, errors.New("mofn: 秘密为空")
	}
	if k != n {
		// 仅支持"全部在场"（k=n）；真门限（k<n）须厂商机制或另立设计。
		return nil, fmt.Errorf("%w: 软件兜底仅支持 k=n（全部在场），k<n 需厂商 m-of-n", ErrMofNUnsupported)
	}
	shares := make([][]byte, n)
	acc := make([]byte, len(secret))
	for i := 0; i < n-1; i++ {
		s := make([]byte, len(secret))
		if _, err := rand.Read(s); err != nil {
			return nil, fmt.Errorf("mofn: 生成份额失败: %w", err)
		}
		for j := range acc {
			acc[j] ^= s[j]
		}
		shares[i] = s
	}
	shares[n-1] = acc // 最后一份 = 前面异或累积（与 secret 异或即为 secret）
	return shares, nil
}

// Combine 异或重组（份额不足或超额即失败）。
func (SoftwareMofN) Combine(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, fmt.Errorf("mofn: 份额数 %d < 2", len(shares))
	}
	out := make([]byte, len(shares[0]))
	for _, s := range shares {
		if len(s) != len(out) {
			return nil, errors.New("mofn: 份额长度不一致")
		}
		for j := range out {
			out[j] ^= s[j]
		}
	}
	return out, nil
}
