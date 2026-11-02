// embedding_test.go - token 嵌入表（`tok.emb`）的确定性、唯一真值源与边界测试
//
// 背景：T02 发现设计 §2.4.5 的张量枚举漏了嵌入表，而**没有嵌入就跑不了前向**。
// 团队裁定：`tok.emb` 补进 route2plan 枚举、实现落在 route2demo，
// 客户端注入与服务端 Gather 必须共用同一张表。本文件就是这条裁定的机器化证明。
package route2demo

import (
	"testing"

	"security-ai-gateway/gateway/teecore/route2plan"
)

// TestEmbeddingMatchesRawTable 嵌入表必须与 RawWeights(tok.emb) 的对应行**逐位一致**。
//
// route2demo.Embedding 按需只算需要的行，RawWeights 一次派生整张表；二者若哪天
// 用了不同的盐值或下标次序，症状会是"输出随机错 token"且没有任何一层报错。
// 故在此用逐位相等锁死——这就是「客户端注入 == 服务端 Gather」的证明。
func TestEmbeddingMatchesRawTable(t *testing.T) {
	cfg := demoCfg()
	key := TokEmbKey(cfg)
	table, err := RawWeights(cfg, key)
	if err != nil {
		t.Fatalf("RawWeights(tok.emb) 失败: %v", err)
	}
	if len(table) != cfg.Vocab {
		t.Fatalf("嵌入表行数 = %d, want Vocab=%d", len(table), cfg.Vocab)
	}
	tokens := []int{0, 1, 7, 31, cfg.Vocab - 1}
	got, err := Embedding(cfg, tokens)
	if err != nil {
		t.Fatalf("Embedding 失败: %v", err)
	}
	for i, tok := range tokens {
		if len(got[i]) != cfg.Dim {
			t.Fatalf("token %d 的嵌入长度 = %d, want Dim=%d", tok, len(got[i]), cfg.Dim)
		}
		for d := range got[i] {
			if got[i][d] != table[tok][d] {
				t.Fatalf("token %d 第 %d 维: Embedding=%v 与 RawWeights 表=%v 不一致（两张表分叉了）",
					tok, d, got[i][d], table[tok][d])
			}
		}
	}
	// 量化版本的同一张表也必须能取到且形状一致（生产侧如需量化嵌入，走同一 key）
	m, err := TensorWeights(cfg, key)
	if err != nil {
		t.Fatal(err)
	}
	if m.Rows != cfg.Vocab || m.Cols != cfg.Dim {
		t.Fatalf("量化嵌入表形状 = %dx%d, want %dx%d", m.Rows, m.Cols, cfg.Vocab, cfg.Dim)
	}
}

// TestEmbeddingGuards 嵌入接口的确定性、边界与哨兵块号纪律。
func TestEmbeddingGuards(t *testing.T) {
	cfg := demoCfg()
	a, err := Embedding(cfg, []int{3, 4, 5})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Embedding(cfg, []int{3, 4, 5})
	if err != nil {
		t.Fatal(err)
	}
	for i := range a {
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				t.Fatal("嵌入不确定：两次派生不一致")
			}
		}
	}
	// 不同 token 的嵌入不应相同
	if a[0][0] == a[1][0] {
		t.Fatal("不同 token 的嵌入不应相同")
	}
	if _, err := Embedding(cfg, []int{cfg.Vocab}); err == nil {
		t.Error("越界 token 应报错")
	}
	if _, err := Embedding(cfg, []int{-1}); err == nil {
		t.Error("负 token 应报错")
	}
	bad := cfg
	bad.Heads = 3
	if _, err := Embedding(bad, []int{0}); err == nil {
		t.Error("非法 cfg 应报错")
	}
	// 哨兵块号纪律：tok.emb 是全局收尾张量，块内块号必须被拒
	if _, _, err := TensorShape(cfg, route2plan.TensorKey{Block: 0, Tensor: route2plan.TensorTokEmb}); err == nil {
		t.Error("tok.emb 用块内块号应被拒（它是全局收尾张量）")
	}
	if _, err := TensorWeights(cfg, route2plan.TensorKey{Block: cfg.Blocks, Tensor: route2plan.TensorTokEmb}); err != nil {
		t.Errorf("tok.emb 用哨兵块号应被接受: %v", err)
	}
	// 空请求：合法，返回空切片
	empty, err := Embedding(cfg, nil)
	if err != nil {
		t.Fatalf("空 token 列表应合法: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("空请求应返回空切片，got %d 行", len(empty))
	}
}
