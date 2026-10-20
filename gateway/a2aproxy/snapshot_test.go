package a2aproxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testSnapshot(revision uint64, agents int) *Snapshot {
	list := make([]SnapshotAgent, 0, agents)
	for i := 0; i < agents; i++ {
		list = append(list, SnapshotAgent{
			Tenant:          "tenant-a",
			Name:            "agent-" + string(rune('a'+i)),
			Revision:        1,
			Card:            json.RawMessage(`{"name":"x"}`),
			BackendURL:      "http://10.0.0.1:8080",
			SignatureStatus: "valid",
		})
	}
	return &Snapshot{RegistryRevision: revision, GeneratedAt: time.Now().UTC(), Agents: list}
}

func TestSnapshotStoreRejectsRollback(t *testing.T) {
	st := NewSnapshotStore()
	if st.Ready() {
		t.Fatal("empty store must not be ready")
	}
	if err := st.ForceReplace(testSnapshot(5, 1)); err != nil {
		t.Fatalf("force replace: %v", err)
	}
	if !st.Ready() || st.Current().Revision() != 5 {
		t.Fatalf("ready=%v revision=%d", st.Ready(), st.Current().Revision())
	}
	// Higher revision is accepted.
	ok, err := st.Replace(testSnapshot(6, 2))
	if err != nil || !ok {
		t.Fatalf("replace(6) = %v, %v", ok, err)
	}
	if st.Current().Len() != 2 {
		t.Fatalf("len = %d", st.Current().Len())
	}
	// Equal/lower revision is refused (no rollback without restart).
	for _, rev := range []uint64{6, 5, 1} {
		ok, err := st.Replace(testSnapshot(rev, 9))
		if err != nil {
			t.Fatalf("replace(%d): %v", rev, err)
		}
		if ok {
			t.Fatalf("replace(%d) must be refused", rev)
		}
	}
	if st.Current().Revision() != 6 || st.Current().Len() != 2 {
		t.Fatalf("store mutated by stale snapshot: rev=%d len=%d", st.Current().Revision(), st.Current().Len())
	}
	// Lookup uses the tenant/name key.
	if _, found := st.Current().Lookup("tenant-a", "agent-a"); !found {
		t.Fatal("lookup agent-a failed")
	}
	if _, found := st.Current().Lookup("tenant-b", "agent-a"); found {
		t.Fatal("cross-tenant lookup must fail")
	}
}

func TestSnapshotFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snapshot.json")
	raw, err := json.Marshal(testSnapshot(3, 2))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	snap, err := LoadFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if snap.Revision() != 3 || snap.Len() != 2 {
		t.Fatalf("snap = rev %d len %d", snap.Revision(), snap.Len())
	}
	// Corrupt file fails loudly (caller keeps the old snapshot).
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("corrupt snapshot must fail")
	}
}

func TestDecodeSnapshotSkipsBadAgents(t *testing.T) {
	// Agents without tenant/name are skipped by the index; decode succeeds.
	snap, err := DecodeSnapshot([]byte(`{"registry_revision":1,"agents":[{"tenant":"t"}]}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if snap.Len() != 0 {
		t.Fatalf("len = %d, want 0", snap.Len())
	}
	if _, err := DecodeSnapshot([]byte(`not json`)); err == nil {
		t.Fatal("invalid json must fail")
	}
}
