// Package main — 安全计数器共享库（P2-4 T-1.3/T-1.4，多副本部署）。
//
// captcha 签发限流/答案存储与登录失败锁定原为进程内态（单副本约束）；
// 多副本部署下改存共享 SQL 库（sqlite/PG 双方言，经 sqlutil 适配）实现跨副本原子：
//   - captcha_rate_limits：同 IP 小时窗口签发计数（单语句原子 upsert 自增，超限拒签）；
//   - captcha_challenges：验证码答案（SHA-256 哈希、TTL、UPDATE 条件消费 = 原子一次性）；
//   - login_attempts（T-1.4）：登录失败计数与锁定（单语句原子 upsert，达阈值锁定）；
//   - operation_intervals（T-1.5）：密码重置发信最小间隔（单语句原子 check-and-set）；
//   - mfa_states（T-1.5）：管理员 MFA 状态（整条记录 JSON；事务读-改-写跨副本串行）。
//
// S1(7) 进程内态清点收尾（C-18）：captcha 签发限流/答案、登录失败锁定、密码重置
// 发信限频、管理员 MFA 状态**四类组件全部具备共享后端**，统一由
// SECURITY_STORE_PG_DSN 开关（空 = 原进程内/文件实现，默认行为零变化）。
//
// 降级策略（明确选定，非默认可配；P2-1 主理人裁决：维持 fail-open 语义不改）：
//   - PG/共享库操作失败 → 回退到进程内实现（等价 P2-4 之前的单副本旧行为）并告警；
//   - captcha 取 fail-open 取向的理由：captcha 仅为防机器人辅助控制（§6.2），
//     其后端不可用若直接 fail-closed 会挡住所有正常登录/注册（可用性灾难）；
//     回退后每副本仍保留单副本级限流与一次性消费防护；
//   - 登录锁定同样回退到进程内计数 —— **该降级不是"无损"**：降级期间
//     ① 防护强度按副本数放大（有效尝试 ≈ 副本数 × LOGIN_MAX_FAIL）；
//     ② 共享锁定态被架空（副本 A 锁定的账号在副本 B 仍可继续尝试）。
//     维持该取向的理由：回退后不弱于 P2-4 之前的单副本基线；若改 fail-closed，
//     共享库抖动期间所有正常用户登录被拒，属全面可用性事故。
//     **风险与监控要求（须落部署基线）**：该告警为高等级告警，值班须按"登录锁定
//     已降级"处理——监控告警计数、必要时临时降副本数或停用依赖登录锁定的端点。
//   - 开库/建表失败（SECURITY_STORE_PG_DSN 配置了但连不上）→ main fail-closed 拒启动
//     （多副本共享语义不可静默丢失）。
package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
)

// securityDDL 安全计数器表（双方言同一 DDL：sqlite / PG）。
// 时间列用 BIGINT（P2-4 约定：PG 的 INTEGER 为 4 字节，epoch 秒 2038 年溢出；
// sqlite INTEGER 本就 8 字节，同一 DDL 两边等宽）。无 sqlite 特有语法。
const securityDDL = `
CREATE TABLE IF NOT EXISTS captcha_rate_limits (
  ip          TEXT    PRIMARY KEY,
  window_hour BIGINT  NOT NULL,
  hits        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS captcha_challenges (
  id         TEXT    PRIMARY KEY,
  code_hash  TEXT    NOT NULL,
  expires_at BIGINT  NOT NULL,
  consumed   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_captcha_challenge_expires ON captcha_challenges(expires_at);

CREATE TABLE IF NOT EXISTS login_attempts (
  identity     TEXT    PRIMARY KEY,
  failed_count INTEGER NOT NULL DEFAULT 0,
  locked_until BIGINT  NOT NULL DEFAULT 0,
  updated_at   BIGINT  NOT NULL
);

CREATE TABLE IF NOT EXISTS operation_intervals (
  op_key TEXT   PRIMARY KEY,
  last_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS mfa_states (
  sub        TEXT   PRIMARY KEY,
  record     TEXT   NOT NULL,
  updated_at BIGINT NOT NULL
);
`

// securityLockKey 租户安全计数器写临界区的跨副本互斥键（PG advisory xact lock；
// 供 mfaStore 的读-改-写事务使用；captcha/loginGuard/interval 均为单语句原子
// 操作（autocommit 行锁），不取该锁）。
const securityLockKey int64 = 0x53454355 // "SECU"

// openSecurityStore 打开安全计数器共享库并初始化 DDL。
// dsn 由调用方保证格式（PG 连接串或 sqlite 路径）。
func openSecurityStore(d sqlutil.Dialect, dsn string) (*sqlutil.DB, error) {
	db, err := sqlutil.Open(d, dsn, securityLockKey)
	if err != nil {
		return nil, fmt.Errorf("security: open %s: %w", d, err)
	}
	if _, err := db.Exec(securityDDL); err != nil {
		db.Close()
		return nil, fmt.Errorf("security: init schema: %w", err)
	}
	return db, nil
}

// captchaBackend 验证码后端（§6.11 / §10.3 C）：
//   - *captchaStore（tenant_captcha.go）：进程内实现，默认，单副本；
//   - *sqlCaptchaBackend：共享库实现（sqlite/PG），多副本原子。
type captchaBackend interface {
	// Issue 生成验证码：返回 (id, dataURL)；同 IP 超限 → errCaptchaRateLimited。
	Issue(ip string) (id, imageDataURL string, err error)
	// Verify 校验并一次性消费（无论对错都消费，防爆破）；大小写不敏感。
	Verify(id, code string) bool
}

// sqlCaptchaBackend 验证码共享库后端（双方言；多副本共享限流计数与答案）。
// 共享库操作失败时回退进程内实现并告警（降级策略见文件头注释）。
type sqlCaptchaBackend struct {
	db       *sqlutil.DB
	ttl      time.Duration
	ipLimit  int
	fallback *captchaStore // 进程内回退（共享库不可达时的降级路径）
	gcStop   chan struct{} // GC 协程停止信号（nil = 未启动）
	alarm    securityAlarm
}

// newSQLCaptchaBackend 构造共享库验证码后端并启动周期 GC。
// ttlMin 答案 TTL 分钟；ipLimitPerHour 同 IP 小时窗口上限。
func newSQLCaptchaBackend(db *sqlutil.DB, ttlMin, ipLimitPerHour int) *sqlCaptchaBackend {
	b := &sqlCaptchaBackend{
		db:       db,
		ttl:      time.Duration(ttlMin) * time.Minute,
		ipLimit:  ipLimitPerHour,
		fallback: newCaptchaStore(ttlMin, ipLimitPerHour),
	}
	b.startGC(5 * time.Minute)
	return b
}

// normalizeCaptchaCode 归一化待比对验证码（与内存实现 EqualFold+TrimSpace 等价；
// 字符集为 ASCII 大写，ToUpper 足够）。
func normalizeCaptchaCode(code string) string {
	return strings.ToUpper(strings.TrimSpace(code))
}

// captchaCodeHash 答案哈希（库内不存明文；SHA-256 定长 + 常量时间比对）。
func captchaCodeHash(code string) string {
	sum := sha256.Sum256([]byte(normalizeCaptchaCode(code)))
	return hex.EncodeToString(sum[:])
}

// Issue 签发验证码：限流计数原子 upsert → 超限拒签（fail-closed）；
// 答案以哈希入库。共享库失败 → 回退进程内并告警。
func (b *sqlCaptchaBackend) Issue(ip string) (id, imageDataURL string, err error) {
	id, imageDataURL, err = b.issueSQL(ip)
	if err != nil && !errors.Is(err, errCaptchaRateLimited) {
		b.alarm.logf("captcha-issue", "captcha 共享库签发失败，回退进程内（降级）：%v", err)
		return b.fallback.Issue(ip)
	}
	return id, imageDataURL, err
}

// issueSQL 共享库签发路径。window 为固定小时窗口起点（测试可注入旧值模拟时钟漂移）。
func (b *sqlCaptchaBackend) issueSQL(ip string) (string, string, error) {
	return b.issueSQLAt(ip, time.Now().Unix()/3600)
}

// issueSQLAt 共享库签发路径（可指定窗口，供 P3-1 回归用例注入漂移窗口）。
func (b *sqlCaptchaBackend) issueSQLAt(ip string, window int64) (string, string, error) {
	now := time.Now()
	// 单语句原子 upsert 自增：跨副本并发签发在行锁上串行，计数无丢失。
	// 窗口语义（QA P3-1）：窗口**只前进不回退**——整点边界并发或副本间时钟漂移时，
	// 带着旧窗口的迟到请求必须计入当前窗口（hits 累加），既不得把 window_hour 拉回
	// 旧值，也不得把 hits 重置为 1（否则限流额度被放大）。
	//   - 请求窗口 == 当前窗口 → 累加；
	//   - 请求窗口 > 当前窗口 → 窗口前移，计数从 1 重开；
	//   - 请求窗口 < 当前窗口（迟到/漂移）→ 窗口不动，累加。
	// 标量取大：sqlite MAX(a,b) / PG GREATEST(a,b)（与 tenant_store.go 同款方言分支）。
	winExpr := "MAX(captcha_rate_limits.window_hour, EXCLUDED.window_hour)"
	if b.db.Dialect().IsPostgres() {
		winExpr = "GREATEST(captcha_rate_limits.window_hour, EXCLUDED.window_hour)"
	}
	var hits int
	if err := b.db.QueryRow(`INSERT INTO captcha_rate_limits (ip, window_hour, hits)
		VALUES (?, ?, 1)
		ON CONFLICT (ip) DO UPDATE SET
			window_hour = `+winExpr+`,
			hits = CASE WHEN `+winExpr+` = captcha_rate_limits.window_hour
				THEN captcha_rate_limits.hits + 1 ELSE 1 END
		RETURNING hits`, ip, window).Scan(&hits); err != nil {
		return "", "", err
	}
	// 语义与内存实现对齐：第 ipLimit 次放行，第 ipLimit+1 次拒签。
	if b.ipLimit > 0 && hits > b.ipLimit {
		return "", "", errCaptchaRateLimited
	}

	code, err := randomCaptchaCode(captchaLength)
	if err != nil {
		return "", "", err
	}
	id, err := randomToken(16)
	if err != nil {
		return "", "", err
	}
	pngBytes, err := renderCaptchaPNG(code)
	if err != nil {
		return "", "", err
	}
	if _, err := b.db.Exec(`INSERT INTO captcha_challenges (id, code_hash, expires_at, consumed)
		VALUES (?, ?, ?, 0)`, id, captchaCodeHash(code), now.Add(b.ttl).Unix()); err != nil {
		return "", "", err
	}
	return id, "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngBytes), nil
}

// Verify 原子一次性消费 + 常量时间比对。共享库失败 → 回退进程内并告警。
// 双向覆盖混合降级态（QA P3-3）：
//   - 共享库签发 + 共享库抖动期间校验 → 回退进程内（该图中途不可校验，用户重试即可）；
//   - 降级态内存签发 + 共享库恢复后校验 → 库中无此 id，同样回退进程内命中。
func (b *sqlCaptchaBackend) Verify(id, code string) bool {
	if id == "" || code == "" {
		return false
	}
	ok, err := b.verifySQL(id, code)
	if err != nil {
		b.alarm.logf("captcha-verify", "captcha 共享库校验失败，回退进程内（降级）：%v", err)
		return b.fallback.Verify(id, code)
	}
	if !ok {
		// 库中无该 id（未命中/已消费/已过期）：再试进程内副本，覆盖内存签发的图。
		// 命中即消费（同一次性语义），不因混用两种后端放宽防爆破。
		return b.fallback.Verify(id, code)
	}
	return true
}

// verifySQL 共享库校验路径：单语句原子消费并直取哈希（QA P3-2：
// UPDATE ... RETURNING 一次拿到 code_hash，避免"消费后读哈希"与 GC 的边界竞争）。
func (b *sqlCaptchaBackend) verifySQL(id, code string) (bool, error) {
	now := time.Now().Unix()
	// 原子一次性消费：仅未消费且未过期的行可置 consumed=1；并发校验同一 id
	// 时仅一个请求能 RETURNING 到哈希。
	var stored string
	err := b.db.QueryRow(`UPDATE captcha_challenges SET consumed = 1
		WHERE id = ? AND consumed = 0 AND expires_at > ?
		RETURNING code_hash`, id, now).Scan(&stored)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil // 无此 id / 已消费 / 已过期
		}
		return false, err
	}
	// 常量时间比对，防计时侧信道。
	return subtle.ConstantTimeCompare([]byte(stored), []byte(captchaCodeHash(code))) == 1, nil
}

// startGC 启动周期清理协程（复用既有后台 ticker 模式；承载全部安全计数器表的
// 过期行清理——captcha 挑战/限流行 + 发信限频陈旧行）。
// 已消费但未过期的挑战行保留（verifySQL 消费后还要读哈希）。
func (b *sqlCaptchaBackend) startGC(interval time.Duration) {
	b.gcStop = make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				securityGCOnce(b.db, &b.alarm)
			case <-b.gcStop:
				return
			}
		}
	}()
}

// securityGCOnce 一轮安全计数器过期行清理（mfa_states 为长期状态，不清理）。
func securityGCOnce(db *sqlutil.DB, alarm *securityAlarm) {
	now := time.Now().Unix()
	if _, err := db.Exec(`DELETE FROM captcha_challenges WHERE expires_at <= ?`, now); err != nil {
		alarm.logf("captcha-gc", "captcha 过期挑战清理失败：%v", err)
	}
	if _, err := db.Exec(`DELETE FROM captcha_rate_limits WHERE window_hour < ?`, now/3600-1); err != nil {
		alarm.logf("captcha-gc", "captcha 陈旧限流行清理失败：%v", err)
	}
	// 发信限频行：超过 24h 未再触发即清理（避免按邮箱无限增长）。
	if _, err := db.Exec(`DELETE FROM operation_intervals WHERE last_at < ?`, now-86400); err != nil {
		alarm.logf("interval-gc", "发信限频陈旧行清理失败：%v", err)
	}
	// 登录失败计数：24h 未再触发且当前未处于锁定窗口的行清理（QA P3-4；
	// 未清理会让未达阈值且不再回来的 identity 在共享库跨副本永久累积）。
	if _, err := db.Exec(`DELETE FROM login_attempts WHERE updated_at < ? AND locked_until <= ?`, now-86400, now); err != nil {
		alarm.logf("login-gc", "登录失败计数陈旧行清理失败：%v", err)
	}
}

// stopGC 停止周期清理协程（测试用；生产随进程退出）。
func (b *sqlCaptchaBackend) stopGC() {
	if b.gcStop != nil {
		close(b.gcStop)
		b.gcStop = nil
	}
}

// securityAlarm 限频告警（同类 ≥60s 一条，防共享库故障时日志风暴）。
type securityAlarm struct {
	mu   sync.Mutex
	last map[string]int64 // op → 最近告警 unix 秒
}

// logf 记录一条限频告警。
func (a *securityAlarm) logf(op, format string, args ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.last == nil {
		a.last = make(map[string]int64)
	}
	now := time.Now().Unix()
	if now-a.last[op] < 60 {
		return
	}
	a.last[op] = now
	log.Printf("[security-store] "+format, args...)
}

// securitySharedDB 已启用的安全计数器共享库句柄（useSecurityPGStore 注入）；
// 供 mfaStore 等在自身初始化点读取开关（nil = 未启用，各组件走原进程内/文件实现）。
var securitySharedDB *sqlutil.DB

// useSecurityPGStore 将 handler 的安全计数器切换到共享库后端（main.go 接线用，
// 仅在 SECURITY_STORE_PG_DSN 配置时调用；缺省保持进程内实现，行为不变）。
func (h *tenantHandler) useSecurityPGStore(db *sqlutil.DB) {
	securitySharedDB = db
	if h.cfg.captchaEnabled {
		h.captcha = newSQLCaptchaBackend(db, h.cfg.captchaTTLMin, h.cfg.captchaIPRatePerHour)
	}
	// T-1.4：登录失败锁定同库切换（阈值/窗口沿用既有 loginGuard 配置，语义不变）。
	h.loginGuard = newSQLLoginGuard(db, h.cfg.loginMaxFail, h.cfg.loginLockMin)
	// T-1.5：密码重置发信限频同库切换（最小间隔沿用既有配置，语义不变）。
	h.resetGuard = newSQLIntervalGuard(db, h.cfg.passwordResetIntervalMin)
	// T-1.5：mfaStore 经 securitySharedDB 开关注入（loadMFAStore 读取，见 mfa.go）。
}

// ---------- 登录失败锁定共享库后端（P2-4 T-1.4，S1(7) login_attempts）----------

// sqlLoginGuardBackend 登录失败锁定共享库后端（双方言；多副本共享计数，
// 不存在按副本放大）。共享库操作失败时回退进程内实现（等价单副本旧行为）并告警。
type sqlLoginGuardBackend struct {
	db       *sqlutil.DB
	maxFail  int
	lockDur  time.Duration
	fallback *memoryLoginGuard // 进程内回退（共享库不可达时的降级路径）
	alarm    securityAlarm
}

// newSQLLoginGuard 构造共享库登录锁定门禁。
func newSQLLoginGuard(db *sqlutil.DB, maxFail, lockMin int) *loginGuard {
	return &loginGuard{backend: &sqlLoginGuardBackend{
		db:       db,
		maxFail:  maxFail,
		lockDur:  time.Duration(lockMin) * time.Minute,
		fallback: newMemoryLoginGuard(maxFail, lockMin),
	}}
}

// isLocked 锁定窗口内直接拒绝。过期锁定记录即删（等价内存实现：
// 锁定过期后计数清零重新累计）。identity 在后端入口归一化（QA P3-6）。
func (g *sqlLoginGuardBackend) isLocked(identity string) bool {
	id := normalizeEmail(identity)
	locked, err := g.isLockedSQL(id)
	if err != nil {
		g.alarm.logf("login-isLocked", "ALERT 高等级：登录锁定共享库查询失败，已降级为进程内计数——防护强度按副本数放大（有效尝试 ≈ 副本数 × LOGIN_MAX_FAIL），共享锁定态被架空: %v", err)
		return g.fallback.isLocked(id)
	}
	return locked
}

func (g *sqlLoginGuardBackend) isLockedSQL(identity string) (bool, error) {
	now := time.Now().Unix()
	if _, err := g.db.Exec(`DELETE FROM login_attempts
		WHERE identity = ? AND locked_until > 0 AND locked_until <= ?`, identity, now); err != nil {
		return false, err
	}
	var lockedUntil int64
	switch err := g.db.QueryRow(`SELECT locked_until FROM login_attempts WHERE identity = ?`, identity).Scan(&lockedUntil); {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, err
	}
	return lockedUntil > now, nil
}

// onFail 失败原子自增；达阈值进入锁定窗口（单语句 upsert，跨副本原子无丢失）。
// 语义与内存实现逐条对齐：计数持续累加，达阈值后每次失败都顺延锁定窗口。
func (g *sqlLoginGuardBackend) onFail(identity string) {
	id := normalizeEmail(identity)
	if err := g.onFailSQL(id); err != nil {
		g.alarm.logf("login-onFail", "ALERT 高等级：登录失败计数共享库写入失败，已降级为进程内计数——防护强度按副本数放大（有效尝试 ≈ 副本数 × LOGIN_MAX_FAIL）: %v", err)
		g.fallback.onFail(id)
	}
}

// onFailSQL 原子自增并在达阈值时置锁定。maxFail ≤ 0 一律不锁定（QA P2-2）：
// 与内存侧 `if g.maxFail > 0 && ...` 语义一致——运维常以 LOGIN_MAX_FAIL=0 表"关闭锁定"，
// 若 SQL 侧无此守卫则 `1 >= 0` 恒真 → 第一次输错即锁定（正常用户被锁死）。
func (g *sqlLoginGuardBackend) onFailSQL(identity string) error {
	now := time.Now().Unix()
	lockUntil := now + int64(g.lockDur/time.Second)
	_, err := g.db.Exec(`INSERT INTO login_attempts (identity, failed_count, locked_until, updated_at)
		VALUES (?, 1, CASE WHEN ? > 0 AND 1 >= ? THEN ? ELSE 0 END, ?)
		ON CONFLICT (identity) DO UPDATE SET
			failed_count = login_attempts.failed_count + 1,
			locked_until = CASE WHEN ? > 0 AND login_attempts.failed_count + 1 >= ? THEN ? ELSE 0 END,
			updated_at = EXCLUDED.updated_at`,
		identity, g.maxFail, g.maxFail, lockUntil, now, g.maxFail, g.maxFail, lockUntil)
	return err
}

// onSuccess 登录成功清零（删记录）。
func (g *sqlLoginGuardBackend) onSuccess(identity string) {
	id := normalizeEmail(identity)
	if _, err := g.db.Exec(`DELETE FROM login_attempts WHERE identity = ?`, id); err != nil {
		g.alarm.logf("login-onSuccess", "登录成功清零共享库删除失败，回退进程内（降级）：%v", err)
		g.fallback.onSuccess(id)
	}
}

// ---------- 发信限频共享库后端（P2-4 T-1.5，operation_intervals）----------

// sqlIntervalGuard 最小操作间隔的共享库后端（双方言；多副本共享计数，
// 无按副本放大——同邮箱重置发信在各副本共用一个计数）。
// 共享库失败 → 回退进程内实现（等价单副本旧行为）并告警。
type sqlIntervalGuard struct {
	db       *sqlutil.DB
	dur      time.Duration
	fallback *memoryIntervalGuard
	alarm    securityAlarm
}

// newSQLIntervalGuard 构造共享库发信限频门禁（min 为最小间隔分钟数）。
func newSQLIntervalGuard(db *sqlutil.DB, min int) *intervalGuard {
	return &intervalGuard{backend: &sqlIntervalGuard{
		db:       db,
		dur:      time.Duration(min) * time.Minute,
		fallback: newMemoryIntervalGuard(min),
	}}
}

// allow 距上次操作超过间隔则记录并返回 true，否则 false。
// 单语句原子 check-and-set：首次（INSERT）或间隔已过（ON CONFLICT DO UPDATE
// ... WHERE 满足）会返回一行 = 放行；间隔未到 → 无返回行 = 拒发（原子跨副本）。
// 注：库内按秒记时间，与内存实现的 time.Time 精度差 ≤1s，语义等价。
func (g *sqlIntervalGuard) allow(key string) bool {
	now := time.Now().Unix()
	rows, err := g.db.Query(`INSERT INTO operation_intervals (op_key, last_at) VALUES (?, ?)
		ON CONFLICT (op_key) DO UPDATE SET last_at = excluded.last_at
		WHERE operation_intervals.last_at <= ?
		RETURNING 1`, key, now, now-int64(g.dur/time.Second))
	if err != nil {
		g.alarm.logf("interval-allow", "发信限频共享库访问失败，回退进程内（降级）：%v", err)
		return g.fallback.allow(key)
	}
	allowed := rows.Next()
	_ = rows.Close()
	return allowed
}
