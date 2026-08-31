package secagg

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
)

func testConfig(n, t, dim int) Config {
	return Config{
		NumParties: n,
		Threshold:  t,
		Modulus:    DefaultModulus,
		Dimension:  dim,
	}
}

// randVector 生成 [0, R) 随机向量。
func randVector(r uint64, dim int) []uint64 {
	v := make([]uint64, dim)
	for i := range v {
		n, _ := rand.Int(rand.Reader, new(big.Int).SetUint64(r))
		v[i] = n.Uint64()
	}
	return v
}

func sumVectors(vs [][]uint64, mod uint64) []uint64 {
	if len(vs) == 0 {
		return nil
	}
	sum := make([]uint64, len(vs[0]))
	for _, v := range vs {
		for i := range sum {
			sum[i] = addMod(sum[i], v[i], mod)
		}
	}
	return sum
}

// newParties 构造 n 个参与方（ID 0..n-1，输入 values）。
func newParties(cfg Config, values [][]uint64) []*party {
	ps := make([]*party, len(values))
	for i, v := range values {
		p, err := NewParty(i, v, cfg, nil)
		if err != nil {
			panic(err)
		}
		ps[i] = p
	}
	return ps
}

// runAll 将本地参与方转换为 PartyDriver 后驱动聚合（测试 helper）。
func runAll(agg *Aggregator, ps []*party) (*Result, error) {
	ds := make([]PartyDriver, len(ps))
	for i, p := range ps {
		ds[i] = p
	}
	return agg.Run(ds)
}

// G-01 正常聚合：输出 == 明文和。
func TestAggregateCorrect(t *testing.T) {
	cfg := testConfig(4, 3, 8)
	values := [][]uint64{randVector(cfg.Modulus, 8), randVector(cfg.Modulus, 8), randVector(cfg.Modulus, 8), randVector(cfg.Modulus, 8)}
	parties := newParties(cfg, values)

	agg, err := NewAggregator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := runAll(agg, parties)
	if err != nil {
		t.Fatal(err)
	}
	want := sumVectors(values, cfg.Modulus)
	if len(res.Sum) != len(want) {
		t.Fatalf("结果维度 %d != %d", len(res.Sum), len(want))
	}
	for i := range want {
		if res.Sum[i] != want[i] {
			t.Fatalf("分量 %d 错误: got=%d want=%d", i, res.Sum[i], want[i])
		}
	}
	if len(res.OnlineIDs) != 4 {
		t.Fatalf("在线用户数 %d != 4", len(res.OnlineIDs))
	}
}

// G-01b 多组随机配置回归。
func TestAggregateCorrectManyConfigs(t *testing.T) {
	configs := []struct{ n, t, dim int }{
		{3, 2, 4}, {4, 3, 1}, {5, 3, 16}, {6, 4, 8}, {7, 4, 32}, {10, 6, 8},
	}
	for _, c := range configs {
		cfg := testConfig(c.n, c.t, c.dim)
		values := make([][]uint64, c.n)
		for i := range values {
			values[i] = randVector(cfg.Modulus, c.dim)
		}
		agg, _ := NewAggregator(cfg)
		res, err := runAll(agg, newParties(cfg, values))
		if err != nil {
			t.Fatalf("n=%d t=%d 失败: %v", c.n, c.t, err)
		}
		want := sumVectors(values, cfg.Modulus)
		for i := range want {
			if res.Sum[i] != want[i] {
				t.Fatalf("n=%d t=%d 分量 %d 错误: got=%d want=%d", c.n, c.t, i, res.Sum[i], want[i])
			}
		}
	}
}

// G-02 单用户掉线：输出 == 在线用户和。
func TestAggregateSingleDropout(t *testing.T) {
	cfg := testConfig(4, 3, 8)
	values := [][]uint64{randVector(cfg.Modulus, 8), randVector(cfg.Modulus, 8), randVector(cfg.Modulus, 8), randVector(cfg.Modulus, 8)}
	parties := newParties(cfg, values)

	// 参与方 3 在 Round2（上传阶段）掉线
	parties[3].dropAt = Round2MaskedInput

	agg, _ := NewAggregator(cfg)
	res, err := runAll(agg, parties)
	if err != nil {
		t.Fatal(err)
	}
	want := sumVectors(values[:3], cfg.Modulus)
	for i := range want {
		if res.Sum[i] != want[i] {
			t.Fatalf("分量 %d 错误: got=%d want=%d", i, res.Sum[i], want[i])
		}
	}
	if len(res.OnlineIDs) != 3 {
		t.Fatalf("在线用户数 %d != 3", len(res.OnlineIDs))
	}
}

// G-02b 不同阶段掉线回归（Round1 前、Round1、Round2、Round4）。
func TestAggregateDropoutAtVariousRounds(t *testing.T) {
	for _, round := range []Round{Round0Advertise, Round1ShareSeeds, Round2MaskedInput, Round4Unmask} {
		cfg := testConfig(5, 3, 8)
		values := make([][]uint64, 5)
		for i := range values {
			values[i] = randVector(cfg.Modulus, 8)
		}
		parties := newParties(cfg, values)
		parties[4].dropAt = round

		agg, _ := NewAggregator(cfg)
		res, err := runAll(agg, parties)
		if err != nil {
			t.Fatalf("round=%v 掉线失败: %v", round, err)
		}
		// Round4 掉线时用户 4 已上传输入（U3 语义），结果包含其输入；
		// 其余阶段掉线则结果仅含前 4 人。
		expected := values[:4]
		if round == Round4Unmask {
			expected = values
		}
		want := sumVectors(expected, cfg.Modulus)
		for i := range want {
			if res.Sum[i] != want[i] {
				t.Fatalf("round=%v 分量 %d 错误: got=%d want=%d", round, i, res.Sum[i], want[i])
			}
		}
	}
}

// G-03 大量掉线：在线 < t 时安全中止，绝不输出部分结果。
func TestAggregateTooManyDropouts(t *testing.T) {
	cfg := testConfig(4, 3, 8)
	values := make([][]uint64, 4)
	for i := range values {
		values[i] = randVector(cfg.Modulus, 8)
	}
	parties := newParties(cfg, values)
	parties[2].dropAt = Round2MaskedInput
	parties[3].dropAt = Round2MaskedInput

	agg, _ := NewAggregator(cfg)
	_, err := runAll(agg, parties)
	if !errors.Is(err, ErrInsufficientParties) {
		t.Fatalf("应返回 ErrInsufficientParties，got %v", err)
	}
}

// G-04 份额交付规则（T2 防护的结构性验证）：
// 对在线用户只提交 b 份额、绝无成对种子份额。
func TestUnmaskShareIsolation(t *testing.T) {
	cfg := testConfig(4, 3, 8)
	values := make([][]uint64, 4)
	for i := range values {
		values[i] = randVector(cfg.Modulus, 8)
	}
	parties := newParties(cfg, values)
	// 参与方 3 掉线（模拟真实掉线者），其余在线
	parties[3].dropAt = Round2MaskedInput

	agg, _ := NewAggregator(cfg)
	// 跑完整协议，随后检查 unmask 交付
	res, err := runAll(agg, parties)
	if err != nil {
		t.Fatal(err)
	}
	_ = res

	// 结构性断言：验证份额交付规则
	online := map[int]bool{0: true, 1: true, 2: true, 3: false}
	for _, p := range parties[:3] {
		um, err := p.unmask(context.Background(), online)
		if err != nil {
			t.Fatal(err)
		}
		// 在线用户 0/1/2 必须有 b 份额
		for _, v := range []int{0, 1, 2} {
			if _, ok := um.SelfMaskShares[v]; !ok {
				t.Fatalf("参与方 %d 未提交在线用户 %d 的 b 份额", p.id, v)
			}
		}
		// 掉线者 3 的种子份额应只针对在线用户
		for v, inner := range um.DroppedSeedShares {
			if v != 3 {
				t.Fatalf("参与方 %d 提交了非掉线者 %d 的种子份额", p.id, v)
			}
			for u := range inner {
				if !online[u] {
					t.Fatalf("种子份额针对非在线用户 %d", u)
				}
			}
		}
	}
}

// G-06 非法输入校验。
func TestInvalidInputs(t *testing.T) {
	cfg := testConfig(4, 3, 8)

	// 向量越界
	if _, err := NewParty(0, []uint64{cfg.Modulus}, cfg, nil); err == nil {
		t.Fatal("越界输入应报错")
	}
	// 空向量维度
	if _, err := NewParty(0, nil, cfg, nil); err == nil {
		t.Fatal("空向量应报错")
	}
	// 重复 ID
	values := make([][]uint64, 4)
	for i := range values {
		values[i] = randVector(cfg.Modulus, 8)
	}
	parties := newParties(cfg, values)
	dup := parties[0]
	parties[3] = dup
	agg, _ := NewAggregator(cfg)
	if _, err := runAll(agg, parties); err == nil {
		t.Fatal("重复 ID 应报错")
	}
	// 数量不匹配
	agg2, _ := NewAggregator(cfg)
	if _, err := runAll(agg2, parties[:3]); err == nil {
		t.Fatal("参与方数量不匹配应报错")
	}
	// 非法配置
	if _, err := NewAggregator(testConfig(2, 2, 8)); err == nil {
		t.Fatal("n<3 应报错")
	}
	if _, err := NewAggregator(testConfig(4, 2, 8)); err == nil {
		t.Fatal("t≤n/2 应报错")
	}
}

// G-07 掉线风暴下的快速失败（安全中止路径无 goroutine 泄漏）。
func TestSafeAbort(t *testing.T) {
	cfg := testConfig(4, 3, 8)
	values := make([][]uint64, 4)
	for i := range values {
		values[i] = randVector(cfg.Modulus, 8)
	}
	parties := newParties(cfg, values)
	parties[1].dropAt = Round1ShareSeeds
	parties[2].dropAt = Round1ShareSeeds
	parties[3].dropAt = Round1ShareSeeds

	agg, _ := NewAggregator(cfg)
	if _, err := runAll(agg, parties); !errors.Is(err, ErrInsufficientParties) {
		t.Fatalf("应安全中止，got %v", err)
	}
}

// G-08 并发多会话：互不干扰。
func TestConcurrentSessions(t *testing.T) {
	const sessions = 10
	var wg sync.WaitGroup
	errs := make(chan error, sessions)

	for s := 0; s < sessions; s++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			cfg := testConfig(4, 3, 8)
			values := make([][]uint64, 4)
			for i := range values {
				values[i] = randVector(cfg.Modulus, 8)
			}
			parties := newParties(cfg, values)
			agg, _ := NewAggregator(cfg)
			res, err := runAll(agg, parties)
			if err != nil {
				errs <- err
				return
			}
			want := sumVectors(values, cfg.Modulus)
			for i := range want {
				if res.Sum[i] != want[i] {
					errs <- fmt.Errorf("会话 %d 分量 %d 错误", seed, i)
					return
				}
			}
			errs <- nil
		}(s)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// G-01c 空输入集：Aggregator 对空参与方列表显式报错。
func TestEmptyParties(t *testing.T) {
	cfg := testConfig(4, 3, 8)
	agg, _ := NewAggregator(cfg)
	if _, err := runAll(agg, nil); err == nil {
		t.Fatal("空参与方应报错")
	}
}

// --- 恶意敌手模式专项测试（Round 3 签名 + 承诺校验）---

// newSignedParties 构造带可信身份密钥的参与方（恶意敌手模式测试 helper）。
func newSignedParties(cfg Config, values [][]uint64) ([]*party, map[int]ed25519.PublicKey) {
	trusted := make(map[int]ed25519.PublicKey, len(values))
	ps := make([]*party, len(values))
	for i, v := range values {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		trusted[i] = pub
		p, err := NewParty(i, v, cfg, priv)
		if err != nil {
			panic(err)
		}
		ps[i] = p
	}
	return ps, trusted
}

// G-11 恶意敌手模式：可信密钥 + 签名校验下正常聚合。
func TestMaliciousModeCorrect(t *testing.T) {
	cfg := testConfig(4, 3, 8)
	// 预置会话 ID（生产环境由聚合器生成并分发给各方）
	cfg.SessionID = make([]byte, SessionIDLen)
	rand.Read(cfg.SessionID)
	values := [][]uint64{randVector(cfg.Modulus, 8), randVector(cfg.Modulus, 8), randVector(cfg.Modulus, 8), randVector(cfg.Modulus, 8)}
	parties, trusted := newSignedParties(cfg, values)
	cfg.TrustedSignKeys = trusted

	agg, err := NewAggregator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := runAll(agg, parties)
	if err != nil {
		t.Fatal(err)
	}
	want := sumVectors(values, cfg.Modulus)
	for i := range want {
		if res.Sum[i] != want[i] {
			t.Fatalf("分量 %d 错误: got=%d want=%d", i, res.Sum[i], want[i])
		}
	}
}

// G-12 身份冒充攻击检测：通告 ID 与 driver 身份不一致时中止。
func TestIDSpoofingDetection(t *testing.T) {
	cfg := testConfig(4, 3, 8)
	values := make([][]uint64, 4)
	for i := range values {
		values[i] = randVector(cfg.Modulus, 8)
	}
	parties := newParties(cfg, values)

	// 手动篡改某方的通告 ID（模拟身份冒充）
	// 通过包装一个 spoofingParty 实现
	spoofed := make([]PartyDriver, 4)
	for i, p := range parties {
		if i == 2 {
			spoofed[i] = &spoofParty{party: p, fakeID: 1}
		} else {
			spoofed[i] = p
		}
	}
	agg, _ := NewAggregator(cfg)
	_, err := agg.Run(spoofed)
	if err == nil {
		t.Fatal("身份冒充应被检测到")
	}
}

// spoofParty 包装真实 party，在 advertise 时返回伪造 ID（用于测试身份检测）。
type spoofParty struct {
	party  *party
	fakeID int
}

func (s *spoofParty) partyID() int                     { return s.party.partyID() }
func (s *spoofParty) dropped(round Round) bool         { return s.party.dropped(round) }
func (s *spoofParty) receiveBundles(ctx context.Context, b []shareBundleCipher) error {
	return s.party.receiveBundles(ctx, b)
}
func (s *spoofParty) maskedInput(ctx context.Context, a map[int]advertiseMsg) ([]uint64, error) {
	return s.party.maskedInput(ctx, a)
}
func (s *spoofParty) unmask(ctx context.Context, o map[int]bool) (unmaskMsg, error) {
	return s.party.unmask(ctx, o)
}
func (s *spoofParty) shareSeeds(ctx context.Context, a map[int]advertiseMsg) ([]shareBundleCipher, seedCommitments, error) {
	return s.party.shareSeeds(ctx, a)
}
func (s *spoofParty) advertise(ctx context.Context) (advertiseMsg, error) {
	adv, err := s.party.advertise(ctx)
	if err != nil {
		return adv, err
	}
	adv.ID = s.fakeID // 伪造 ID
	return adv, nil
}

// G-13 非法签名检测：可信密钥表启用时，签名无效则中止。
// 测试场景：参与方签名的 sessionID 与聚合器不一致（重放攻击模拟）。
func TestInvalidSignatureDetection(t *testing.T) {
	cfg := testConfig(4, 3, 8)
	cfg.SessionID = make([]byte, SessionIDLen)
	rand.Read(cfg.SessionID)
	values := make([][]uint64, 4)
	for i := range values {
		values[i] = randVector(cfg.Modulus, 8)
	}
	parties, trusted := newSignedParties(cfg, values)
	cfg.TrustedSignKeys = trusted

	// 使用不同的 sessionID 构造聚合器（模拟重放/会话不匹配）
	wrongCfg := cfg
	wrongCfg.SessionID = make([]byte, SessionIDLen)
	rand.Read(wrongCfg.SessionID)
	agg, _ := NewAggregator(wrongCfg)
	_, err := runAll(agg, parties)
	if !errors.Is(err, ErrSignatureVerification) {
		t.Fatalf("签名无效（sessionID 不匹配）应返回 ErrSignatureVerification，got: %v", err)
	}
}

// G-13b 公钥不匹配检测：通告 SignPub 与可信表不一致时中止。
func TestSignPubMismatchDetection(t *testing.T) {
	cfg := testConfig(4, 3, 8)
	cfg.SessionID = make([]byte, SessionIDLen)
	rand.Read(cfg.SessionID)
	values := make([][]uint64, 4)
	for i := range values {
		values[i] = randVector(cfg.Modulus, 8)
	}
	parties, trusted := newSignedParties(cfg, values)
	// 将 2 号的可信公钥替换为随机值
	fakePub, _, _ := ed25519.GenerateKey(rand.Reader)
	trusted[2] = fakePub
	cfg.TrustedSignKeys = trusted

	agg, _ := NewAggregator(cfg)
	_, err := runAll(agg, parties)
	if err == nil {
		t.Fatal("公钥不匹配应被检测到")
	}
}

// G-14 ID 越界防御：NewParty 拒绝 id >= NumParties。
func TestPartyIDOutOfRangeRejected(t *testing.T) {
	cfg := testConfig(4, 3, 8)
	if _, err := NewParty(10, []uint64{1, 2}, cfg, nil); err == nil {
		t.Fatal("ID >= NumParties 应被拒绝")
	}
	if _, err := NewParty(-1, []uint64{1, 2}, cfg, nil); err == nil {
		t.Fatal("负 ID 应被拒绝")
	}
}

// G-15 会话 ID 自动生成：NewAggregator 未指定 SessionID 时自动生成。
func TestSessionIDAutoGenerate(t *testing.T) {
	cfg := testConfig(4, 3, 8)
	agg, err := NewAggregator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sid := agg.SessionID()
	if len(sid) != SessionIDLen {
		t.Fatalf("会话 ID 长度 %d != %d", len(sid), SessionIDLen)
	}
	// 两次构造应不同
	agg2, _ := NewAggregator(cfg)
	sid2 := agg2.SessionID()
	if string(sid) == string(sid2) {
		t.Fatal("两次构造的会话 ID 不应相同")
	}
}
