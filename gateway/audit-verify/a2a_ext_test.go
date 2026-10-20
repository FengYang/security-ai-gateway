package auditverify

import (
	"strings"
	"testing"
)

// A2A 注册中心的扩展元数据字段（证据字段，**不进 hash**）。
//
// 冻结清单 §5.7 要求 A2A 审计事件携带 actor_tenant/target_tenant/agent/provider/
// old_revision/new_revision/content_hash/reason/trace_id 等字段。这些字段挂在
// policyaudit.Event 上但**不进 hash()**（core schema 的哈希字段序是跨包硬约束，
// 不得增删），故对独立验证器而言：**多出的 JSON 字段必须既不破坏链校验、
// 也不影响重算结果**。
//
// 本测试在验证器侧（不 import 服务端代码）构造 core schema 事件并附加这些字段，
// 断言：① 链仍校验通过；② 重算哈希与无扩展字段时**逐字节相同**（扩展字段确实不参与哈希）。
const a2aExtFields = `,"actor_tenant":"tenant-a","target_tenant":"tenant-b","agent":"research-agent",` +
	`"provider":"team-research","old_revision":1,"new_revision":2,` +
	`"content_hash":"sha256:deadbeef","reason":"","trace_id":"trace-1"`

// TestCoreSchemaIgnoresA2AExtensionFields core schema 校验链时忽略 A2A 扩展字段。
func TestCoreSchemaIgnoresA2AExtensionFields(t *testing.T) {
	schema, err := SchemaFor("core")
	if err != nil {
		t.Fatal(err)
	}
	// 与既有 core 固定向量同源的最小事件（字段集与 core schema 一致）。
	const evA = `{"event_id":"a2a-e1","timestamp":1700000000000000000,"actor":"alice",` +
		`"action":"a2a.agent.register","version_from":0,"version_to":1,"rule_id":"tenant-a/research-agent",` +
		`"change":"added","field":"team-research","old_value":"","new_value":"sha256:abc",` +
		`"request_id":"req-1","result":"ok"}`
	const evB = `{"event_id":"a2a-e2","timestamp":1700000000000000001,"actor":"alice",` +
		`"action":"a2a.agent.update","version_from":1,"version_to":2,"rule_id":"tenant-a/research-agent",` +
		`"change":"updated","field":"team-research","old_value":"sha256:abc","new_value":"sha256:def",` +
		`"request_id":"req-2","result":"ok","prev_hash":"7dc37927b76c5d1c55700621bb270479f61743946147c521d667011705280a8d"}`

	// 基线（无扩展字段）。
	base, err := VerifyReader(strings.NewReader(evA+"\n"+evB+"\n"), schema)
	if err != nil {
		t.Fatalf("基线链校验失败: %v", err)
	}
	if !base.OK || base.Events != 2 {
		t.Fatalf("基线链应完整，实际 ok=%v events=%d", base.OK, base.Events)
	}

	// 附加 A2A 扩展字段后重算。
	extA := strings.Replace(evA, `"result":"ok"}`, `"result":"ok"`+a2aExtFields+`}`, 1)
	extB := strings.Replace(evB, `"result":"ok",`, `"result":"ok"`+a2aExtFields+`,`, 1)
	ext, err := VerifyReader(strings.NewReader(extA+"\n"+extB+"\n"), schema)
	if err != nil {
		t.Fatalf("带扩展字段的链校验失败: %v", err)
	}
	if !ext.OK || ext.Events != 2 {
		t.Fatalf("带扩展字段的链应完整，实际 ok=%v events=%d", ext.OK, ext.Events)
	}
	// 关键断言：重算结果逐字节相同 ⇒ 扩展字段确实不参与哈希。
	if ext.LastHash != base.LastHash {
		t.Fatalf("扩展字段改变了重算哈希（应不参与 hash）：base=%s ext=%s", base.LastHash, ext.LastHash)
	}
}

// TestCoreSchemaA2AExtensionTamperNotDetected 扩展字段被篡改**不**导致链断裂。
//
// 这是「证据字段不进 hash」的**已知且被接受**的性质：扩展元数据不在哈希保护范围内，
// 故其完整性依赖 WORM 文件的只追加属性与链上哈希字段（如 content_hash）本身。
// 本测试把该性质固化为显式契约，避免日后有人误以为扩展字段受哈希保护。
func TestCoreSchemaA2AExtensionTamperNotDetected(t *testing.T) {
	schema, _ := SchemaFor("core")
	const evA = `{"event_id":"a2a-e1","timestamp":1700000000000000000,"actor":"alice",` +
		`"action":"a2a.agent.register","version_from":0,"version_to":1,"rule_id":"tenant-a/research-agent",` +
		`"change":"added","field":"team-research","old_value":"","new_value":"sha256:abc",` +
		`"request_id":"req-1","result":"ok"}`
	extA := strings.Replace(evA, `"result":"ok"}`, `"result":"ok"`+a2aExtFields+`}`, 1)
	tampered := strings.Replace(extA, `"trace_id":"trace-1"`, `"trace_id":"trace-forged"`, 1)

	res, err := VerifyReader(strings.NewReader(tampered+"\n"), schema)
	if err != nil {
		t.Fatalf("验证器报错: %v", err)
	}
	if !res.OK {
		t.Fatal("篡改扩展字段不应导致链断裂（扩展字段不在 hash 保护范围内）")
	}
}
