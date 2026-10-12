package cryptopmodule

// backend_failover.go —— FailoverBackend：实现 ModuleBackend 并委派给 FailoverManager.Active()。
//
// 用途：包裹 moduleProvider 的后端，使 Provider 20 方法零改动获得主备 / 熔断能力（M5）。
// 运算失败/成功时回调管理器（熔断计数）；无可用后端（fail-closed）时统一返回
// ErrModuleUnavailable，绝不静默降级（C-3 / D-6）。

// FailoverBackend 包装 FailoverManager，对外呈 ModuleBackend 语义。
type FailoverBackend struct {
	fm *FailoverManager
}

// NewFailoverBackend 以管理器构造包装后端。
func NewFailoverBackend(fm *FailoverManager) *FailoverBackend {
	return &FailoverBackend{fm: fm}
}

// Init 主/备已由调用方 Init；此处仅能力复核 + 启动探针（HealthInterval<=0 时仅手动探针）。
func (fb *FailoverBackend) Init(cfg *Config) error {
	if err := CheckCapabilities(fb.fm.primary.Capabilities(), cfg.RequiredMechanisms); err != nil {
		return err
	}
	fb.fm.Start()
	return nil
}

// Capabilities 上报主模块能力（备仅作冗余，对外能力等同主）。
func (fb *FailoverBackend) Capabilities() Capabilities {
	return fb.fm.primary.Capabilities()
}

// AcquireSession 从 active 后端会话池获取会话。
func (fb *FailoverBackend) AcquireSession() (Session, error) {
	b, peer, err := fb.fm.Active()
	if err != nil {
		return 0, err
	}
	s, e := b.AcquireSession()
	fb.note(peer, e)
	return s, e
}

// ReleaseSession 归还会话到 active 后端池。
func (fb *FailoverBackend) ReleaseSession(s Session) error {
	b, peer, err := fb.fm.Active()
	if err != nil {
		return err
	}
	e := b.ReleaseSession(s)
	fb.note(peer, e)
	return e
}

// Health 返回主模块健康（对外健康探测以主为准；切换态由 State() 表达）。
func (fb *FailoverBackend) Health() HealthLevel {
	return fb.fm.primary.Health()
}

// Close 停止探针并关闭主/备后端。
func (fb *FailoverBackend) Close() error {
	fb.fm.Stop()
	var firstErr error
	if err := fb.fm.primary.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if fb.fm.backup != nil {
		if err := fb.fm.backup.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ---- 对称运算 ----

// Seal SM4-GCM 加密（经 active 后端）。
func (fb *FailoverBackend) Seal(keyRef KeyRef, nonce, plaintext, aad []byte) ([]byte, error) {
	b, peer, err := fb.fm.Active()
	if err != nil {
		return nil, err
	}
	out, e := b.Seal(keyRef, nonce, plaintext, aad)
	fb.note(peer, e)
	return out, e
}

// Open SM4-GCM 解密（经 active 后端）。
func (fb *FailoverBackend) Open(keyRef KeyRef, nonce, ciphertext, aad []byte) ([]byte, error) {
	b, peer, err := fb.fm.Active()
	if err != nil {
		return nil, err
	}
	out, e := b.Open(keyRef, nonce, ciphertext, aad)
	fb.note(peer, e)
	return out, e
}

// Hash SM3（无密钥；免会话）。
func (fb *FailoverBackend) Hash(data []byte) ([]byte, error) {
	b, peer, err := fb.fm.Active()
	if err != nil {
		return nil, err
	}
	out, e := b.Hash(data)
	fb.note(peer, e)
	return out, e
}

// HMAC HMAC-SM3。
func (fb *FailoverBackend) HMAC(keyRef KeyRef, data []byte) ([]byte, error) {
	b, peer, err := fb.fm.Active()
	if err != nil {
		return nil, err
	}
	out, e := b.HMAC(keyRef, data)
	fb.note(peer, e)
	return out, e
}

// KDF SM3-KDF 派生（父 token 不出模块）。
func (fb *FailoverBackend) KDF(parentRef KeyRef, salt, info []byte, outLen int, alias string) ([]byte, error) {
	b, peer, err := fb.fm.Active()
	if err != nil {
		return nil, err
	}
	out, e := b.KDF(parentRef, salt, info, outLen, alias)
	fb.note(peer, e)
	return out, e
}

// Rand 生成随机数（须来自模块 CSPRNG，GM2-03）。
func (fb *FailoverBackend) Rand(n int) ([]byte, error) {
	b, peer, err := fb.fm.Active()
	if err != nil {
		return nil, err
	}
	out, e := b.Rand(n)
	fb.note(peer, e)
	return out, e
}

// ---- 非对称运算 ----

// Sign SM2 签名。
func (fb *FailoverBackend) Sign(privRef KeyRef, msg []byte, uid string) ([]byte, error) {
	b, peer, err := fb.fm.Active()
	if err != nil {
		return nil, err
	}
	out, e := b.Sign(privRef, msg, uid)
	fb.note(peer, e)
	return out, e
}

// Verify SM2 验签（pub 为原始字节，无需 active 后端，但为统一口径仍经 active）。
func (fb *FailoverBackend) Verify(pub, msg, sig []byte, uid string) error {
	b, peer, err := fb.fm.Active()
	if err != nil {
		return err
	}
	e := b.Verify(pub, msg, sig, uid)
	fb.note(peer, e)
	return e
}

// GenerateKeyPair SM2 密钥对。
func (fb *FailoverBackend) GenerateKeyPair(usage string) (KeyRef, []byte, error) {
	b, peer, err := fb.fm.Active()
	if err != nil {
		return nil, nil, err
	}
	ref, pub, e := b.GenerateKeyPair(usage)
	fb.note(peer, e)
	return ref, pub, e
}

// ECDH SM2 密钥协商。
func (fb *FailoverBackend) ECDH(privRef KeyRef, peerPub []byte) ([]byte, error) {
	b, peer, err := fb.fm.Active()
	if err != nil {
		return nil, err
	}
	out, e := b.ECDH(privRef, peerPub)
	fb.note(peer, e)
	return out, e
}

// ---- 密钥管理 ----

// WrapKey 以 KEK 封装 DEK（模块内封装）。
func (fb *FailoverBackend) WrapKey(kekRef KeyRef, dek []byte) ([]byte, error) {
	b, peer, err := fb.fm.Active()
	if err != nil {
		return nil, err
	}
	out, e := b.WrapKey(kekRef, dek)
	fb.note(peer, e)
	return out, e
}

// UnwrapKey 以 KEK 解封 DEK。
func (fb *FailoverBackend) UnwrapKey(kekRef KeyRef, wrapped []byte) ([]byte, error) {
	b, peer, err := fb.fm.Active()
	if err != nil {
		return nil, err
	}
	out, e := b.UnwrapKey(kekRef, wrapped)
	fb.note(peer, e)
	return out, e
}

// ImportKey 导入外部密钥字节（M4 路径）。
func (fb *FailoverBackend) ImportKey(spec string, key []byte, alias string) (KeyRef, error) {
	b, peer, err := fb.fm.Active()
	if err != nil {
		return nil, err
	}
	ref, e := b.ImportKey(spec, key, alias)
	fb.note(peer, e)
	return ref, e
}

// GenerateKey 生成对称密钥对象。
func (fb *FailoverBackend) GenerateKey(spec, alias string) (KeyRef, error) {
	b, peer, err := fb.fm.Active()
	if err != nil {
		return nil, err
	}
	ref, e := b.GenerateKey(spec, alias)
	fb.note(peer, e)
	return ref, e
}

// DestroyKey 销毁模块内密钥对象。
func (fb *FailoverBackend) DestroyKey(keyRef KeyRef) error {
	b, peer, err := fb.fm.Active()
	if err != nil {
		return err
	}
	e := b.DestroyKey(keyRef)
	fb.note(peer, e)
	return e
}

// RotateKey 模块内密钥轮换。
func (fb *FailoverBackend) RotateKey(oldRef KeyRef, spec string) (KeyRef, error) {
	b, peer, err := fb.fm.Active()
	if err != nil {
		return nil, err
	}
	ref, e := b.RotateKey(oldRef, spec)
	fb.note(peer, e)
	return ref, e
}

// note 运算结果回调（成功复位熔断，失败累加熔断计数）。
func (fb *FailoverBackend) note(peer Peer, err error) {
	if err != nil {
		fb.fm.ReportOpError(peer)
	} else {
		fb.fm.ReportOpSuccess(peer)
	}
}

// 编译期契约保证。
var _ ModuleBackend = (*FailoverBackend)(nil)
