// 溯源要素（synthetic/producer/content_id）编解码 + 透传；
// 未设置时不得出现在 JSON（前向兼容：旧上游 / 旧客户端零影响）。
package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestChunkLabelProvenanceRoundtrip 溯源要素往返；未设置时省略。
func TestChunkLabelProvenanceRoundtrip(t *testing.T) {
	in := streamChunk{Seq: 1, Delta: "内容由人工智能生成", Label: &chunkLabel{
		Std: "GB45438-2025", Position: labelPositionHead,
		Synthetic: true, Producer: "P-001", ContentID: "req-123",
	}}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out streamChunk
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Label == nil || !out.Label.Synthetic || out.Label.Producer != "P-001" || out.Label.ContentID != "req-123" {
		t.Fatalf("溯源要素 roundtrip 不符：%+v", out.Label)
	}

	rawOld, err := json.Marshal(streamChunk{Seq: 1, Delta: "x", Label: &chunkLabel{Std: "GB45438-2025", Position: labelPositionHead}})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"synthetic"`, `"producer"`, `"content_id"`} {
		if strings.Contains(string(rawOld), k) {
			t.Fatalf("未设置时不得出现 %s：%s", k, rawOld)
		}
	}
}
