package main

// P1b 待办3：流完成收尾清理测试。
// cleanupRespKeys 为纯逻辑（不依赖 proxywasm hostcall），直接在 KeyStore 全局上验证：
// 异常中断流（fail-closed 截断/客户端断连）时应兜底删除登记密钥，且对已消费删除的 key 幂等。

import "testing"

// TestCleanupRespKeys 验证 onStreamDone 的兜底密钥清理。
func TestCleanupRespKeys(t *testing.T) {
	// 清空 KeyStore 全局，测试结束复原。
	KeyStore.keys = map[string][]byte{}
	t.Cleanup(func() { KeyStore.keys = map[string][]byte{} })

	// 构造：本请求登记 2 个 key（均未消费 → 模拟流在 endOfStream 前被截断）。
	st := &respStreamState{keys: []string{"k-request", "k-nonce"}}
	KeyStore.Store("k-request", []byte("seed-request"))
	KeyStore.Store("k-nonce", []byte("seed-nonce"))

	cleanupRespKeys(st)

	// 兜底删除后密钥不可再回溯。
	if _, ok := KeyStore.Lookup("k-request"); ok {
		t.Fatalf("cleanupRespKeys 未删除登记密钥 k-request")
	}
	if _, ok := KeyStore.Lookup("k-nonce"); ok {
		t.Fatalf("cleanupRespKeys 未删除登记密钥 k-nonce")
	}
	if st.keys != nil {
		t.Fatalf("cleanupRespKeys 未清空 respStreamState.keys")
	}
}

// TestCleanupRespKeysIdempotent 验证正常消费 ident 幂等：key 已在解密路径删除，再次清理不误伤。
func TestCleanupRespKeysIdempotent(t *testing.T) {
	KeyStore.keys = map[string][]byte{}
	t.Cleanup(func() { KeyStore.keys = map[string][]byte{} })

	// key 已正常消费（解密后 Delete），但登记表仍残留（onStreamDone 恒触发）。
	KeyStore.Store("k-consumed", []byte("seed-consumed"))
	KeyStore.Delete("k-consumed") // 模拟正常解密路径已删除
	st := &respStreamState{keys: []string{"k-consumed"}}

	cleanupRespKeys(st)

	if _, ok := KeyStore.Lookup("k-consumed"); ok {
		t.Fatalf("已消费密钥仍可回溯")
	}
	if len(st.keys) != 0 {
		t.Fatalf("cleanupRespKeys 未清空登记表")
	}
}