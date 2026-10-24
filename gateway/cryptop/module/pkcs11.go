//go:build pkcs11

// pkcs11.go —— PKCS#11（Cryptoki）后端绑定（P1-5 §7.4，M4-1）。
//
// 定位：ModuleBackend 的 PKCS#11 实现，把统一语义映射到 C_* 调用。生产路径的
// 密码运算仍在模块内执行，本文件只做接口调用/编码转换/会话与健康编排
// （B-6.1-8），不自研密码（C-4）。
//
// M4-1 范围（首个可提交切片）：
//   - 生命周期：Init（库加载/初始化/槽位/登录/能力探测/会话池）、Capabilities、
//     AcquireSession/ReleaseSession、Health、Close；
//   - Rand（C_GenerateRandom，模块 CSPRNG；GM/T 0050 启动自检 R-S3-12 留 M4-2）；
//   - 其余密码运算方法返回 ErrNotImplemented——fail-closed（C-3），
//     待厂商机制映射逐步接入，**绝不回退软件实现冒充合规**。
//
// 接入进度（子任务编号）：
//   - M4-2（ee11d99）：随机数质量启动自检 R-S3-12（randtest.go）；
//   - M4-3（c83a9c3）：厂商机制 profile 常量表与解析框架（mechprofile.go）；
//   - M4-4a：GenerateKey/ImportKey/DestroyKey + KeyRef 编解码
//     （pkcs11key.go / keyref.go）；
//   - M4-4b：Seal/Open/HMAC/WrapKey/UnwrapKey/KDF（pkcs11sym.go）；
//   - 其余运算（Hash/Sign/Verify/GenerateKeyPair/ECDH/RotateKey）仍
//     fail-closed，随 M4-4c 接入。
//
// 机制 profile（B-6.1-2）：PKCS#11 v3.0 未定义 SM 机制的 CKM 标准值（SM 支持
// 属厂商扩展），机制名→CKM 映射按厂商 profile 常量表登记；softhsm 档经
// 2026-10-24 实测（pkcs11-tool -M，SoftHSM v2.6）：token 无任何 SM 机制，
// 仅 AES-GCM 与 CKM_AES_KEY_WRAP。厂商 HSM 接入时按厂商文档扩充本表。
// Capabilities 只登记**探测命中**的机制，未命中即缺（R-S3-11 启动拒），
// 禁止把 AES 等非国密机制映射成 SM 机制名冒充合规。
//
// 槽位语义（实现期裁决）：module_slot = GetSlotList(tokenPresent=true) 的
// **下标**（0 = 第一个带 token 的槽位），不用厂商派生的 64 位 slot ID 配置
// （token 重建后 ID 会变）。
package cryptopmodule

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

// 厂商机制 profile（B-6.1-2）由 mechprofile.go 承载：CKM → 机制名翻译表
// 来自 module_mechanism_profile 配置的 JSON 文件（每厂商一份，按厂商 SDK
// 文档登记；PKCS#11 v3.0 无 SM 机制标准 CKM 值，禁止臆测）。未配置 profile
// 时仅 rand 恒登记（C_GenerateRandom 为 PKCS#11 通用函数，不依赖
// mechanism list）。

// PKCS11Backend PKCS#11 后端（M4-1）。
type PKCS11Backend struct {
	mu            sync.Mutex
	cfg           *Config
	ctx           *pkcs11.Ctx
	slotIndex     int // module_slot 语义：GetSlotList 下标（见包注释）
	caps          Capabilities
	pool          *SessionPool
	loginSH       pkcs11.SessionHandle // Init 登录会话（token 级登录态载体）
	hasLogin      bool
	closed        bool
	randHealth    RandHealthStatus // R-S3-12 随机数启动自检状态（零值=未检）
	mech          *MechTable       // B-6.1-2 机制翻译表（profile 驱动；空表=仅 rand）
	mechProfileID string           // profile 溯源（Capabilities.Profile）
}

// newPKCS11Backend 构造并初始化 PKCS#11 后端（NewBackend 的生产入口）。
func newPKCS11Backend(cfg *Config) (ModuleBackend, error) {
	if cfg == nil {
		return nil, fmt.Errorf("module: nil config")
	}
	b := &PKCS11Backend{cfg: cfg}
	if err := b.Init(cfg); err != nil {
		b.Close() // 清理半初始化状态（fail-closed）
		return nil, err
	}
	return b, nil
}

// ---- 生命周期 ----

// Init 加载厂商库并完成启动校验（R-S3-1/R-S3-2/R-S3-11；失败即启动拒，C-3）。
func (b *PKCS11Backend) Init(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("pkcs11: nil config")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cfg = cfg

	// R-S3-2：口令仅经引用名解析（file:/env: 载体；字面值拒绝）。
	pin, err := resolveModulePIN(cfg.PinRef)
	if err != nil {
		return err
	}

	// R-S3-1：库可加载。
	b.ctx = pkcs11.New(cfg.LibPath)
	if b.ctx == nil {
		return fmt.Errorf("%w: pkcs11.New(%s) 失败（R-S3-1）", ErrModuleUnavailable, cfg.LibPath)
	}
	if err := b.ctx.Initialize(); err != nil {
		return fmt.Errorf("%w: C_Initialize(%s): %v（R-S3-1）", ErrModuleUnavailable, cfg.LibPath, err)
	}

	// 槽位（下标语义）与 token 校验。
	slots, err := b.ctx.GetSlotList(true)
	if err != nil {
		return fmt.Errorf("%w: C_GetSlotList: %v", ErrModuleUnavailable, err)
	}
	if cfg.Slot < 0 || cfg.Slot >= len(slots) {
		return fmt.Errorf("%w: module_slot=%d 越界（带 token 的槽位共 %d 个；语义为 GetSlotList 下标）",
			ErrModuleUnavailable, cfg.Slot, len(slots))
	}
	slotID := slots[cfg.Slot]
	tok, err := b.ctx.GetTokenInfo(slotID)
	if err != nil {
		return fmt.Errorf("%w: C_GetTokenInfo(slot=%d): %v", ErrModuleUnavailable, cfg.Slot, err)
	}
	b.slotIndex = cfg.Slot

	// 登录（token 级登录态；登录后零化本地口令副本，R-S3-2）。
	loginSH, err := b.ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return fmt.Errorf("%w: C_OpenSession(登录): %v", ErrModuleUnavailable, err)
	}
	b.loginSH = loginSH
	b.hasLogin = true
	if err := b.ctx.Login(loginSH, pkcs11.CKU_USER, pin); err != nil {
		return fmt.Errorf("%w: C_Login(user): %v（R-S3-2/R-S3-10）", ErrModuleUnavailable, err)
	}
	// R-S3-2 已知限制（M4-1 如实登记）：miekg/pkcs11 的 C_Login 形参为 string，
	// 绑定层内部会产生不可零化的字符串副本；本处零化本地 []byte 副本，
	// 完整零化需绑定层提供 []byte 形参或厂商直连绑定（S3-a 选型时评估）。
	pinBytes := []byte(pin)
	zeroBytes(pinBytes)

	// B-6.1-2：厂商机制 profile 加载（fail-closed；Validate 已预校验，此处
	// 转为运行表）。空 = 仅 rand 恒登记（SoftHSM 等无 SM 机制环境的缺省态）。
	if cfg.MechanismProfile != "" {
		p, err := LoadMechProfile(cfg.MechanismProfile)
		if err != nil {
			return err
		}
		b.mech = p.Table()
		b.mechProfileID = p.ProfileID
	} else {
		b.mech = EmptyMechTable()
	}

	// 能力探测（B-6.1-6/R-S3-11）：只登记探测命中的机制。
	caps, raw, err := b.probeCapabilities(slotID, tok)
	if err != nil {
		return err
	}
	if err := CheckCapabilities(caps, cfg.RequiredMechanisms); err != nil {
		return fmt.Errorf("%w（模块实测机制 CKM: %v；已登记: %v）", err, raw, caps.Mechanisms)
	}
	b.caps = caps

	// 会话池（B-6.1-7）：factory 开 serial **读写**会话（token 登录态对
	// 所有会话生效）。CKF_RW_SESSION 必需：密钥对象管理（C_GenerateKey/
	// C_CreateObject/C_DestroyObject）与 Seal/Sign 等写路径在只读会话上
	// 返回 CKR_SESSION_READ_ONLY（M4-4a 真机实测 0xB5）；只读操作
	// （Rand/Hash/Verify）在 RW 会话上同样合法，无副作用。
	pool, err := NewSessionPool(cfg.MaxSessions, cfg.SessionQueueSize,
		func() (Session, error) {
			sh, err := b.ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
			if err != nil {
				return 0, fmt.Errorf("%w: C_OpenSession: %v", ErrModuleUnavailable, err)
			}
			return Session(sh), nil
		},
		func(s Session) error {
			if err := b.ctx.CloseSession(pkcs11.SessionHandle(s)); err != nil {
				return fmt.Errorf("%w: C_CloseSession: %v", ErrModuleUnavailable, err)
			}
			return nil
		})
	if err != nil {
		return err
	}
	b.pool = pool

	// R-S3-12（GM2-03）：随机数质量启动自检（quick 档 20000bit 三项）。
	// 失败即启动拒（与 R-S3-11 同权）；power-on 全量档仅用于 S3-a 到货验收/
	// 密评留档（randtest.go），不在启动路径。
	if _, err := b.runRandSelfCheckLocked(RandCheckQuick); err != nil {
		return err
	}
	return nil
}

// probeCapabilities 机制探测：GetMechanismList → 查厂商 profile 表 → 机制名。
// rand 恒登记（C_GenerateRandom 通用）。返回 (能力, 原始 CKM 列表, 错误)。
func (b *PKCS11Backend) probeCapabilities(slotID uint, tok pkcs11.TokenInfo) (Capabilities, []uint, error) {
	mechs, err := b.ctx.GetMechanismList(slotID)
	if err != nil {
		return Capabilities{}, nil, fmt.Errorf("%w: C_GetMechanismList: %v", ErrModuleUnavailable, err)
	}
	raw := make([]uint, 0, len(mechs))
	names := make([]string, 0, len(mechs)+1)
	names = append(names, MechRand) // C_GenerateRandom 不依赖 mechanism list
	for _, m := range mechs {
		raw = append(raw, m.Mechanism)
		if name, ok := b.mech.NameByCKM(m.Mechanism); ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return Capabilities{
		Backend:    BackendPKCS11,
		Vendor:     strings.TrimSpace(tok.ManufacturerID),
		Model:      strings.TrimSpace(tok.Model),
		Mechanisms: names,
		Profile:    b.mechProfileID,
	}, raw, nil
}

// Capabilities 能力快照（探测值副本；R-S3-11 禁止仅靠 profile 静态宣称）。
func (b *PKCS11Backend) Capabilities() Capabilities {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.caps
	c.Mechanisms = append([]string(nil), b.caps.Mechanisms...)
	return c
}

// AcquireSession 从会话池获取会话（池满排队；超限失败）。
func (b *PKCS11Backend) AcquireSession() (Session, error) {
	b.mu.Lock()
	pool := b.pool
	b.mu.Unlock()
	if pool == nil {
		return 0, fmt.Errorf("%w: 后端未初始化", ErrModuleUnavailable)
	}
	return pool.Acquire()
}

// ReleaseSession 归还会话到池。
func (b *PKCS11Backend) ReleaseSession(s Session) error {
	b.mu.Lock()
	pool := b.pool
	b.mu.Unlock()
	if pool == nil {
		return fmt.Errorf("%w: 后端未初始化", ErrModuleUnavailable)
	}
	return pool.Release(s)
}

// Health 分级健康探针（GM2-08；M4-1 简化为模块级 C_GetTokenInfo 探活，
// 连续失败计数由 FailoverManager 承载。注：持锁执行 C 调用，探针与池操作
// 互斥——M4-1 可接受；后续可改"持锁取快照、锁外调用"降低互斥）。
func (b *PKCS11Backend) Health() HealthLevel {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.ctx == nil {
		return HealthDown
	}
	slots, err := b.ctx.GetSlotList(true)
	if err != nil || b.slotIndex < 0 || b.slotIndex >= len(slots) {
		return HealthDown
	}
	if _, err := b.ctx.GetTokenInfo(slots[b.slotIndex]); err != nil {
		return HealthDown
	}
	return HealthOK
}

// Close 释放资源：登出 → 关登录会话 → 关池 → C_Finalize（幂等）。
func (b *PKCS11Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	if b.ctx == nil {
		return nil
	}
	if b.hasLogin {
		_ = b.ctx.Logout(b.loginSH)
		_ = b.ctx.CloseSession(b.loginSH)
		b.hasLogin = false
	}
	if b.pool != nil {
		_ = b.pool.Close()
	}
	if err := b.ctx.Finalize(); err != nil {
		return fmt.Errorf("%w: C_Finalize: %v", ErrModuleUnavailable, err)
	}
	return nil
}

// ---- 对称运算（M4-1：Rand；其余 M4-2 厂商机制映射）----

// Rand 模块 CSPRNG 随机数（GM2-03）。
//
// R-S3-12：首次输出前确保随机数质量启动自检已通过（Init 已检；直接构造
// 等绕过 Init 的路径在此惰性补检）；自检失败 fail-closed——不把不合格
// 随机数送出上层。
func (b *PKCS11Backend) Rand(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("pkcs11: Rand(n=%d) 须 > 0", n)
	}
	if err := b.ensureRandHealthy(); err != nil {
		return nil, err
	}
	return b.randRaw(n)
}

// randRaw 不经自检守卫的 C_GenerateRandom（会话走池；对外输出路径）。
func (b *PKCS11Backend) randRaw(n int) ([]byte, error) {
	s, err := b.AcquireSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = b.ReleaseSession(s) }()
	out, err := b.ctx.GenerateRandom(pkcs11.SessionHandle(s), n)
	if err != nil {
		return nil, fmt.Errorf("%w: C_GenerateRandom(%d): %v", ErrModuleUnavailable, n, err)
	}
	return out, nil
}

// ensureRandHealthy 随机数启动自检守卫（R-S3-12）：未检则补检，已失败则拒输出。
func (b *PKCS11Backend) ensureRandHealthy() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.ctx == nil {
		return fmt.Errorf("%w: 后端未初始化或已关闭", ErrModuleUnavailable)
	}
	if b.randHealth == RandHealthPassed {
		return nil
	}
	if b.randHealth == RandHealthFailed {
		return fmt.Errorf("%w: 启动自检已判定失败，拒绝输出随机数", ErrRandSelfCheckFailed)
	}
	_, err := b.runRandSelfCheckLocked(RandCheckQuick)
	return err
}

// runRandSelfCheckLocked 执行随机数启动自检并更新健康态（调用方持 b.mu）。
//
// 防重入：不经过 AcquireSession（其内部会再取 b.mu），取样 reader 直接用
// 登录会话 loginSH（token 级登录态对所有会话生效，C_GenerateRandom 合法）。
func (b *PKCS11Backend) runRandSelfCheckLocked(profile RandCheckProfile) (*RandCheckReport, error) {
	if b.closed || b.ctx == nil {
		return nil, fmt.Errorf("%w: 后端未初始化或已关闭", ErrModuleUnavailable)
	}
	rep, err := RunRandSelfCheck(&p11RandReader{b: b}, profile)
	if err != nil {
		b.randHealth = RandHealthFailed
		return nil, fmt.Errorf("%w: 自检执行失败: %v", ErrRandSelfCheckFailed, err)
	}
	if rep.Passed {
		b.randHealth = RandHealthPassed
	} else {
		b.randHealth = RandHealthFailed
	}
	return rep, nil
}

// RandHealth 随机数自检健康态（附录 B 指标 cryptop_module_rand_health：
// 1=通过 / 0=失败 / -1=尚未自检；M5 装配期接入 metrics）。
func (b *PKCS11Backend) RandHealth() RandHealthStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.randHealth
}

// p11RandReader io.Reader 适配：从模块 C_GenerateRandom 流式取随机数
// （自检取样源；与 runRandSelfCheckLocked 同锁域，直接用 loginSH）。
type p11RandReader struct{ b *PKCS11Backend }

func (r *p11RandReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	out, err := r.b.ctx.GenerateRandom(r.b.loginSH, len(p))
	if err != nil {
		return 0, fmt.Errorf("%w: C_GenerateRandom(%d): %v", ErrModuleUnavailable, len(p), err)
	}
	return copy(p, out), nil
}

// ---- 未实现方法（随 M4-4b/M4-4c 逐步接入；fail-closed）----

func (b *PKCS11Backend) Hash(data []byte) ([]byte, error) {
	return nil, p11NotImplemented("Hash")
}

func (b *PKCS11Backend) Sign(privRef KeyRef, msg []byte, uid string) ([]byte, error) {
	return nil, p11NotImplemented("Sign")
}

func (b *PKCS11Backend) Verify(pub, msg, sig []byte, uid string) error {
	return p11NotImplemented("Verify")
}

func (b *PKCS11Backend) GenerateKeyPair(usage string) (KeyRef, []byte, error) {
	return nil, nil, p11NotImplemented("GenerateKeyPair")
}

func (b *PKCS11Backend) ECDH(privRef KeyRef, peerPub []byte) ([]byte, error) {
	return nil, p11NotImplemented("ECDH")
}

func (b *PKCS11Backend) RotateKey(oldRef KeyRef, spec string) (KeyRef, error) {
	return nil, p11NotImplemented("RotateKey")
}

// 已实现并迁出的方法：
//   - M4-4a：GenerateKey/ImportKey/DestroyKey + KeyRef 编解码
//     （pkcs11key.go / keyref.go）；
//   - M4-4b：Seal/Open/HMAC/WrapKey/UnwrapKey/KDF（pkcs11sym.go）。

// p11NotImplemented 未实现方法的统一 fail-closed 错误（随 M4-4b/M4-4c 逐步消除）。
func p11NotImplemented(method string) error {
	return fmt.Errorf("%w: PKCS11Backend.%s 尚未实现（M4-4 厂商机制映射；fail-closed，绝不回退软件实现）",
		ErrNotImplemented, method)
}

// zeroBytes 零化字节切片（口令本地副本；R-S3-2 尽力为零化，
// 绑定层 string 形参副本的限制见 Init 注释）。
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
