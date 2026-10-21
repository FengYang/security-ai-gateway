package a2aguardrail

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"security-ai-gateway/gateway/a2aguardrail/protocol"
)

func writePolicyFile(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func testPolicyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writePolicyFile(t, dir, "categories.json", `[
		{"id":"A1-01","default_level":"high","default_action":"block"},
		{"id":"A4-06","default_level":"high","default_action":"mask"},
		{"id":"A1-07","default_level":"medium","default_action":"flag"},
		{"id":"A5-01","default_level":"low","default_action":"pass"}
	]`)
	writePolicyFile(t, dir, "manifest.json", `{"policy_version":"test-v1"}`)
	writePolicyFile(t, dir, "keywords/a1-01.json", `{
		"category":"A1-01",
		"rules":[{"id":"r-block","keyword":"BADWORD","type":"contains","normalize":"fold"}]
	}`)
	writePolicyFile(t, dir, "keywords/a1-07.json", `{
		"category":"A1-07",
		"rules":[{"id":"r-flag-cat","keyword":"flag-only","type":"contains"}]
	}`)
	writePolicyFile(t, dir, "keywords/a5-01.json", `{
		"category":"A5-01",
		"rules":[{"id":"r-pass-cat","keyword":"pass-only","type":"contains"}]
	}`)
	writePolicyFile(t, dir, "regex/pii.json", `{
		"category":"A4-06",
		"rules":[{"id":"r-phone","keyword":"(^|[^0-9])(1[3-9][0-9]{9})([^0-9]|$)","type":"regex","normalize":"compact"}]
	}`)
	return dir
}

func TestEngineBlock(t *testing.T) {
	e, err := NewEngine(testPolicyDir(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.Check(context.Background(), protocol.Request{Parts: []protocol.Part{{Kind: protocol.PartKindText, Text: "hello BADWORD world"}}})
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != protocol.ActionDeny {
		t.Fatalf("action=%s, want deny", d.Action)
	}
	if !strings.Contains(d.Reason, "A1-01") || !strings.Contains(d.Reason, "r-block") {
		t.Errorf("reason=%q", d.Reason)
	}
	if strings.Contains(d.Reason, "BADWORD") {
		t.Errorf("reason must not contain matched text: %q", d.Reason)
	}
}

func TestEngineRedactPhoneWithSpaces(t *testing.T) {
	e, err := NewEngine(testPolicyDir(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.Check(context.Background(), protocol.Request{Parts: []protocol.Part{{Kind: protocol.PartKindText, Text: "call 138 0013 8000"}}})
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != protocol.ActionRedact {
		t.Fatalf("action=%s, want redact", d.Action)
	}
	if !strings.Contains(d.Reason, "A4-06") {
		t.Errorf("reason=%q", d.Reason)
	}
}

func TestEngineFlagAndPassDoNotBlock(t *testing.T) {
	e, err := NewEngine(testPolicyDir(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.Check(context.Background(), protocol.Request{Parts: []protocol.Part{{Kind: protocol.PartKindText, Text: "flag-only pass-only"}}})
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != protocol.ActionAllow {
		t.Fatalf("action=%s, want allow", d.Action)
	}
}

func TestEngineBlockWinsAcrossParts(t *testing.T) {
	e, err := NewEngine(testPolicyDir(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.Check(context.Background(), protocol.Request{Parts: []protocol.Part{
		{Kind: protocol.PartKindText, Text: "13800138000"},
		{Kind: protocol.PartKindText, Text: "BADWORD"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != protocol.ActionDeny {
		t.Fatalf("action=%s, want deny (block must win over redact)", d.Action)
	}
}

func TestEngineTooLargeDenies(t *testing.T) {
	e, err := NewEngine(testPolicyDir(t), 8)
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.Check(context.Background(), protocol.Request{Parts: []protocol.Part{{Kind: protocol.PartKindText, Text: "0123456789"}}})
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != protocol.ActionDeny || d.Reason != "content_too_large" {
		t.Fatalf("decision=%+v, want deny/content_too_large", d)
	}
}

func TestEngineInvalidRegexFailsStartup(t *testing.T) {
	dir := testPolicyDir(t)
	writePolicyFile(t, dir, "regex/broken.json", `{
		"category":"A4-06",
		"rules":[{"id":"bad","keyword":"[","type":"regex"}]
	}`)
	if _, err := NewEngine(dir, 0); err == nil {
		t.Fatal("expected invalid regex to fail startup")
	}
}

func TestEngineUnknownCategoryFailsStartup(t *testing.T) {
	dir := testPolicyDir(t)
	writePolicyFile(t, dir, "keywords/unknown.json", `{
		"category":"NOPE",
		"rules":[{"id":"x","keyword":"x","type":"contains"}]
	}`)
	if _, err := NewEngine(dir, 0); err == nil {
		t.Fatal("expected unknown category to fail startup")
	}
}

// TestRepositoryPolicyLoads verifies the real policy tree can be consumed
// without translation. It is skipped if the test is run outside the repo.
func TestRepositoryPolicyLoads(t *testing.T) {
	dir := filepath.Join("..", "tee-infer-service", "policy")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("repository policy not available: %v", err)
	}
	e, err := NewEngine(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	st := e.Status()
	if st.Rules < 1000 || st.ActiveRules == 0 {
		t.Fatalf("unexpected policy status: %+v", st)
	}
	if st.PolicyVersion == "unknown" {
		t.Errorf("policy version not loaded: %+v", st)
	}

	// Pick a real block rule from the loaded tree and verify it is reachable.
	var sample string
	for _, r := range e.rules {
		if r.action == protocol.ActionDeny && r.typ == "contains" && r.normalize == "" {
			sample = r.keyword
			break
		}
	}
	if sample == "" {
		t.Skip("no plain block keyword in repository policy")
	}
	d, err := e.Check(context.Background(), protocol.Request{Parts: []protocol.Part{{Kind: protocol.PartKindText, Text: sample}}})
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != protocol.ActionDeny {
		t.Fatalf("real policy keyword did not block: %+v", d)
	}
}
