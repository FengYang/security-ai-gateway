package streamparser

// bench_test.go — P1-6 M6.4：body 阶段采样 CPU 基准（TT2-05/TT2-09）。
//
// 基准口径（如实注记）：
//   - 采样路径 = 插件 M2.1 落地的 SSE 内容增量判定（`NewContentDeltaSSEParser`），
//     即 body 阶段唯一的 P1-6 新增 CPU；逐 chunk `Feed`（首 token 命中后即刻早返回，R2-05）。
//   - 上界路径 = 对全部 1k 帧逐帧执行内容判定内核（`FirstTokenInChunk`），
//     即「不做首 token 早返回」的最坏开销；门禁以该**上界**为准（保守且非平凡）。
//   - 无采样基线 = 同一 chunk 序列的透传复制（body 直通下界），仅作参考。
//   - 参考「1k token 流式响应」= 1000 个 `data:` 内容帧（OpenAI 兼容），按 1KB 分段。
//   - 阈值 < 3% 由 `scripts/bench-ttft.ps1` 换算：`采样 CPU / 参考流时长`（见脚本注释）。

import (
	"fmt"
	"strings"
	"testing"
)

// buildSSE1kTokens 构造 token 个内容帧的 SSE 响应体（每帧 ≈ 48B，含 [DONE]）。
func buildSSE1kTokens(tokens int) []byte {
	var sb strings.Builder
	sb.Grow(tokens*56 + 16)
	for i := 0; i < tokens; i++ {
		fmt.Fprintf(&sb, "data: {\"choices\":[{\"delta\":{\"content\":\"tok%d\"}}]}\n\n", i)
	}
	sb.WriteString("data: [DONE]\n\n")
	return []byte(sb.String())
}

// chunkify 按固定粒度切分（模拟网关 body 分块回调）。
func chunkify(payload []byte, size int) [][]byte {
	var out [][]byte
	for len(payload) > 0 {
		n := size
		if n > len(payload) {
			n = len(payload)
		}
		out = append(out, payload[:n])
		payload = payload[n:]
	}
	return out
}

// buildSSEFrames 逐帧（单个 `data:` 行）返回 1k token 流内容（用于最坏情况内核基准）。
func buildSSEFrames(tokens int) [][]byte {
	out := make([][]byte, 0, tokens)
	for i := 0; i < tokens; i++ {
		out = append(out, []byte(fmt.Sprintf("data: {\"choices\":[{\"delta\":{\"content\":\"tok%d\"}}]}", i)))
	}
	return out
}

// BenchmarkBodySample_1kTokens 采样路径：1k token 流逐块 Feed（首 token 后早返回）。
func BenchmarkBodySample_1kTokens(b *testing.B) {
	chunks := chunkify(buildSSE1kTokens(1000), 1024)
	p := NewContentDeltaSSEParser()
	b.SetBytes(int64(len(buildSSE1kTokens(1000))))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Reset()
		for _, c := range chunks {
			p.Feed(c)
		}
		if !p.FirstTokenSent() {
			b.Fatal("采样路径应已判定首 token")
		}
	}
}

// BenchmarkBodySampleNoEarlyExit_1kTokens 采样 CPU **上界**：对全部 1k 帧逐帧执行内容
// 判定内核（`FirstTokenInChunk`），即「不做首 token 早返回（R2-05）」的最坏开销。
//
// 该上界与 `BenchmarkBodySample_1kTokens`（真实早返回路径）共同界定采样开销：真实值
// 只会更小。门禁以**上界**为准（保守）。
func BenchmarkBodySampleNoEarlyExit_1kTokens(b *testing.B) {
	frames := buildSSEFrames(1000)
	var sink int
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, f := range frames {
			if FirstTokenInChunk(f) {
				sink++
			}
		}
	}
	_ = sink
}

// BenchmarkBodyForward_1kTokens 无采样基线：同 chunk 序列的透传复制（body 直通下界）。
//
// 刻意采用 `append` 复制到复用缓冲并读取首字节回灌 sink，避免编译器把空转循环消除
// （否则基线会被优化为常量、失去对比意义）。
func BenchmarkBodyForward_1kTokens(b *testing.B) {
	chunks := chunkify(buildSSE1kTokens(1000), 1024)
	buf := make([]byte, 0, 1024)
	var sink int
	b.SetBytes(int64(len(buildSSE1kTokens(1000))))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, c := range chunks {
			buf = append(buf[:0], c...)
			if len(buf) > 0 {
				sink += int(buf[0])
			}
		}
	}
	_ = sink
}
