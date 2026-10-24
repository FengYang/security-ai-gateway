package poc

// P11Module 封装 PKCS#11（SoftHSMv2 / 厂商模块）操作，供 V-3/V-4 使用。
//
// 契约锚点（本体 §6.2.2 / §6.2.5 / D-9 / D-10）：
//   - 备份 KEK 与数据密钥均 CKA_SENSITIVE=true / CKA_EXTRACTABLE=false；
//   - ExportWrapped/ImportWrapped 只走 C_WrapKey/C_UnwrapKey，禁止明文出模块；
//   - GroupKeyRef.inner 用持久 CKA_ID 寻址，禁止 CK_OBJECT_HANDLE。

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/pkcs11"
)

// P11Module 一个已初始化并登录的 PKCS#11 会话。
type P11Module struct {
	mod  *pkcs11.Ctx
	slot uint
	sess pkcs11.SessionHandle
}

// OpenP11 初始化模块、按 token label 找槽位、打开会话并登录。
func OpenP11(modulePath, tokenLabel, pin string) (*P11Module, error) {
	m := pkcs11.New(modulePath)
	if err := m.Initialize(); err != nil {
		return nil, fmt.Errorf("poc: C_Initialize 失败: %w", err)
	}
	slots, err := m.GetSlotList(true)
	if err != nil {
		m.Finalize()
		return nil, fmt.Errorf("poc: C_GetSlotList 失败: %w", err)
	}
	var slot uint
	found := false
	for _, sl := range slots {
		ti, err := m.GetTokenInfo(sl)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(ti.Label[:])) == tokenLabel {
			slot, found = sl, true
			break
		}
	}
	if !found {
		m.Finalize()
		return nil, fmt.Errorf("poc: 未找到 label=%q 的 token", tokenLabel)
	}
	sess, err := m.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		m.Finalize()
		return nil, fmt.Errorf("poc: C_OpenSession 失败: %w", err)
	}
	if err := m.Login(sess, pkcs11.CKU_USER, pin); err != nil {
		m.CloseSession(sess)
		m.Finalize()
		return nil, fmt.Errorf("poc: C_Login 失败: %w", err)
	}
	return &P11Module{mod: m, slot: slot, sess: sess}, nil
}

// Close 登出、关会话、终止模块。
func (p *P11Module) Close() {
	if p == nil || p.mod == nil {
		return
	}
	p.mod.Logout(p.sess)
	p.mod.CloseSession(p.sess)
	p.mod.Finalize()
}

// HardRestart 模拟 sidecar 进程重启：完整 C_Logout/C_CloseSession/C_Finalize 后重新初始化。
// 返回**新的会话句柄语境**（对象句柄全部失效，只有持久 CKA_ID 可再寻址）。
func (p *P11Module) HardRestart(pin string) error {
	p.mod.Logout(p.sess)
	if err := p.mod.CloseSession(p.sess); err != nil {
		return fmt.Errorf("poc: C_CloseSession 失败: %w", err)
	}
	if err := p.mod.Finalize(); err != nil {
		return fmt.Errorf("poc: C_Finalize 失败: %w", err)
	}
	if err := p.mod.Initialize(); err != nil {
		return fmt.Errorf("poc: 重启后 C_Initialize 失败: %w", err)
	}
	sess, err := p.mod.OpenSession(p.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("poc: 重启后 C_OpenSession 失败: %w", err)
	}
	if err := p.mod.Login(sess, pkcs11.CKU_USER, pin); err != nil {
		return fmt.Errorf("poc: 重启后 C_Login 失败: %w", err)
	}
	p.sess = sess
	return nil
}

// GenerateSecret 生成对称密钥（默认 AES-256；sensitive/extractable 由调用方通过模板给定）。
func (p *P11Module) GenerateSecret(id, label string, valueLen int, sensitive, extractable, wrap, unwrap, encrypt, decrypt bool) (pkcs11.ObjectHandle, error) {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, sensitive),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, wrap),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, unwrap),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, encrypt),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, decrypt),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(id)),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, valueLen),
	}
	h, err := p.mod.GenerateKey(p.sess,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, tmpl)
	if err != nil {
		return 0, fmt.Errorf("poc: C_GenerateKey(%s) 失败: %w", id, err)
	}
	return h, nil
}

// GenerateSecretWithTrusted 与 GenerateSecret 相同，但附带 CKA_TRUSTED=true（D-20 ① 能力探测）。
func (p *P11Module) GenerateSecretWithTrusted(id, label string, valueLen int) (pkcs11.ObjectHandle, error) {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_TRUSTED, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(id)),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, valueLen),
	}
	h, err := p.mod.GenerateKey(p.sess,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, tmpl)
	if err != nil {
		return 0, err
	}
	return h, nil
}

// WrapKey C_WrapKey：以 wrappingKey 在模块内 wrap targetKey，返回密文 blob。
func (p *P11Module) WrapKey(wrappingKey, targetKey pkcs11.ObjectHandle) ([]byte, error) {
	blob, err := p.mod.WrapKey(p.sess,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP, nil)},
		wrappingKey, targetKey)
	if err != nil {
		return nil, fmt.Errorf("poc: C_WrapKey(CKM_AES_KEY_WRAP) 失败: %w", err)
	}
	return blob, nil
}

// UnwrapKey C_UnwrapKey：在模块内直接建对象（SENSITIVE/EXTRACTABLE 由模板强制）。
func (p *P11Module) UnwrapKey(unwrappingKey pkcs11.ObjectHandle, blob []byte, id, label string) (pkcs11.ObjectHandle, error) {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(id)),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	h, err := p.mod.UnwrapKey(p.sess,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP, nil)},
		unwrappingKey, blob, tmpl)
	if err != nil {
		return 0, fmt.Errorf("poc: C_UnwrapKey(CKM_AES_KEY_WRAP) 失败: %w", err)
	}
	return h, nil
}

// FindByID 按持久 CKA_ID 查找对象（不依赖会话句柄）。
func (p *P11Module) FindByID(id string) (pkcs11.ObjectHandle, error) {
	if err := p.mod.FindObjectsInit(p.sess, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(id)),
	}); err != nil {
		return 0, fmt.Errorf("poc: C_FindObjectsInit 失败: %w", err)
	}
	hs, _, err := p.mod.FindObjects(p.sess, 8)
	if err != nil {
		p.mod.FindObjectsFinal(p.sess)
		return 0, fmt.Errorf("poc: C_FindObjects 失败: %w", err)
	}
	if err := p.mod.FindObjectsFinal(p.sess); err != nil {
		return 0, fmt.Errorf("poc: C_FindObjectsFinal 失败: %w", err)
	}
	if len(hs) == 0 {
		return 0, fmt.Errorf("poc: CKA_ID=%q 未找到对象（fail-closed，不做静默回退）", id)
	}
	return hs[0], nil
}

// GetBoolAttr 读取布尔属性（第二返回值表示属性是否存在）。
func (p *P11Module) GetBoolAttr(h pkcs11.ObjectHandle, attrType uint) (bool, bool, error) {
	attrs, err := p.mod.GetAttributeValue(p.sess, h, []*pkcs11.Attribute{
		pkcs11.NewAttribute(attrType, nil),
	})
	if err != nil {
		return false, false, fmt.Errorf("poc: C_GetAttributeValue(0x%x) 失败: %w", attrType, err)
	}
	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return false, false, nil
	}
	return attrs[0].Value[0] != 0, true, nil
}

// ReadValueAttr 尝试读取 CKA_VALUE；对敏感对象必须失败（CKR_ATTRIBUTE_SENSITIVE）。
func (p *P11Module) ReadValueAttr(h pkcs11.ObjectHandle) ([]byte, error) {
	attrs, err := p.mod.GetAttributeValue(p.sess, h, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return nil, err // 调用方判定是否为 CKR_ATTRIBUTE_SENSITIVE
	}
	if len(attrs) == 0 {
		return nil, fmt.Errorf("poc: CKA_VALUE 属性缺失")
	}
	return attrs[0].Value, nil
}

// IsSensitiveReadError 判断错误链中是否含 CKR_ATTRIBUTE_SENSITIVE。
func IsSensitiveReadError(err error) bool {
	var pe pkcs11.Error
	return errors.As(err, &pe) && pe == pkcs11.CKR_ATTRIBUTE_SENSITIVE
}

// Encrypt AES-CBC 加密（确定性：固定 IV，用于验证密钥材料等价性）。
func (p *P11Module) Encrypt(key pkcs11.ObjectHandle, plaintext []byte) ([]byte, error) {
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = 0x5A
	}
	if err := p.mod.EncryptInit(p.sess,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, iv)}, key); err != nil {
		return nil, fmt.Errorf("poc: C_EncryptInit 失败: %w", err)
	}
	ct, err := p.mod.Encrypt(p.sess, plaintext)
	if err != nil {
		return nil, fmt.Errorf("poc: C_Encrypt 失败: %w", err)
	}
	return ct, nil
}

// Decrypt AES-CBC 解密（与 Encrypt 同一固定 IV）。
func (p *P11Module) Decrypt(key pkcs11.ObjectHandle, ciphertext []byte) ([]byte, error) {
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = 0x5A
	}
	if err := p.mod.DecryptInit(p.sess,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, iv)}, key); err != nil {
		return nil, fmt.Errorf("poc: C_DecryptInit 失败: %w", err)
	}
	pt, err := p.mod.Decrypt(p.sess, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("poc: C_Decrypt 失败: %w", err)
	}
	return pt, nil
}

// Destroy 销毁对象（用例清理）。
func (p *P11Module) Destroy(h pkcs11.ObjectHandle) error {
	if h == 0 {
		return nil
	}
	if err := p.mod.DestroyObject(p.sess, h); err != nil {
		// 对象已不存在视为成功（幂等清理）。
		if pe, ok := err.(pkcs11.Error); ok && pe == pkcs11.CKR_OBJECT_HANDLE_INVALID {
			return nil
		}
		return fmt.Errorf("poc: C_DestroyObject 失败: %w", err)
	}
	return nil
}

// CleanupIDs 销毁指定 CKA_ID 的全部对象（用例前置清理，保证可重复执行）。
func (p *P11Module) CleanupIDs(ids ...string) error {
	for _, id := range ids {
		for {
			h, err := p.FindByID(id)
			if err != nil {
				break // 已清空
			}
			if err := p.Destroy(h); err != nil {
				return err
			}
		}
	}
	return nil
}
