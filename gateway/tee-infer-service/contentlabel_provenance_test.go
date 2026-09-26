// 标识帧携带溯源要素（synthetic / producer / content_id），并验证 omitempty 前向兼容。
package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestContentLabelProvenanceMeta 溯源要素随标识帧下发；off 态不构造注入器。
func TestContentLabelProvenanceMeta(t *testing.T) {
	cfg := resolveContentLabelConfig(contentLabelConfig{Enabled: true, Producer: "P-001"})
	var metas []*chunkLabelMeta
	lbl := newContentLabeler(&cfg, func(_ string, meta *chunkLabelMeta) error {
		metas = append(metas, meta)
		return nil
	})
	if lbl == nil {
		t.Fatal("启用态应返回注入器")
	}
	lbl.contentID = "req-123" // 调用点（streamTextInfer）注入 request_id
	if err := lbl.emitHead(); err != nil {
		t.Fatal(err)
	}
	if err := lbl.emitTail(); err != nil {
		t.Fatal(err)
	}
	if len(metas) != 2 {
		t.Fatalf("应发射 2 帧，得 %d", len(metas))
	}
	for i, m := range metas {
		if m == nil {
			t.Fatalf("第 %d 帧 meta 为空", i)
		}
		if !m.Synthetic || m.Producer != "P-001" || m.ContentID != "req-123" || m.Std != defaultContentLabelStd {
			t.Fatalf("第 %d 帧溯源要素不符：%+v", i, m)
		}
	}
	if metas[0].Position != labelPositionHead || metas[1].Position != labelPositionTail {
		t.Fatalf("位置不符：%s/%s", metas[0].Position, metas[1].Position)
	}

	// off 态：不构造注入器（全路径零行为变化）
	off := defaultContentLabelConfig()
	if newContentLabeler(&off, func(string, *chunkLabelMeta) error { return nil }) != nil {
		t.Fatal("off 态应返回 nil 注入器")
	}
}

// TestContentLabelProvenanceOmitEmpty 未配置 producer / 未注入 content_id 时不得出现在 JSON
// （前向兼容：旧插件/旧客户端不因新增键而改变解析）。
func TestContentLabelProvenanceOmitEmpty(t *testing.T) {
	cfg := resolveContentLabelConfig(contentLabelConfig{Enabled: true})
	lbl := newContentLabeler(&cfg, func(string, *chunkLabelMeta) error { return nil })
	raw, err := json.Marshal(lbl.meta(labelPositionHead))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"producer"`, `"content_id"`} {
		if strings.Contains(string(raw), k) {
			t.Fatalf("未设置时不得出现 %s：%s", k, raw)
		}
	}
	if !strings.Contains(string(raw), `"synthetic":true`) {
		t.Fatalf("标识生效时须带 synthetic:true：%s", raw)
	}
}
