package a2aproxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	sdk "github.com/a2aproject/a2a-go/v2/a2a"
)

// SnapshotAgent is one registry record as distributed to the data plane
// (F-5 §5.8). It carries the raw signed card, the gateway-form URLs and the
// backend address. backend_url is internal-only and must never leak into
// discovery responses, error bodies or logs.
type SnapshotAgent struct {
	Tenant          string            `json:"tenant"`
	Name            string            `json:"name"`
	Revision        uint64            `json:"revision"`
	Card            json.RawMessage   `json:"card"`
	PublicURL       string            `json:"public_url"`
	DiscoveryURL    string            `json:"discovery_url"`
	BackendURL      string            `json:"backend_url"`
	Skills          []SnapshotSkill   `json:"skills"`
	SignatureStatus string            `json:"signature_status"` // valid|invalid
	Labels          map[string]string `json:"labels,omitempty"`
}

// SnapshotSkill is the skill subset the data plane needs for ACL/ratelimit.
type SnapshotSkill struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Snapshot is the full registry view distributed by the control plane.
type Snapshot struct {
	RegistryRevision uint64          `json:"registry_revision"`
	GeneratedAt      time.Time       `json:"generated_at"`
	Agents           []SnapshotAgent `json:"agents"`

	// byKey indexes agents by "tenant\x00name" for O(1) routing.
	byKey map[string]*SnapshotAgent
}

// Lookup resolves an agent by tenant and name.
func (s *Snapshot) Lookup(tenant, name string) (*SnapshotAgent, bool) {
	if s == nil {
		return nil, false
	}
	a, ok := s.byKey[tenant+"\x00"+name]
	return a, ok
}

// Len returns the number of active agents.
func (s *Snapshot) Len() int {
	if s == nil {
		return 0
	}
	return len(s.byKey)
}

// Revision returns the global registry revision.
func (s *Snapshot) Revision() uint64 {
	if s == nil {
		return 0
	}
	return s.RegistryRevision
}

// DecodeSnapshot strictly decodes a registry snapshot payload.
func DecodeSnapshot(raw []byte) (*Snapshot, error) {
	var snap Snapshot
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&snap); err != nil {
		return nil, fmt.Errorf("a2aproxy: decode snapshot: %w", err)
	}
	snap.reindex()
	return &snap, nil
}

func (s *Snapshot) reindex() {
	s.byKey = make(map[string]*SnapshotAgent, len(s.Agents))
	for i := range s.Agents {
		a := &s.Agents[i]
		if a.Tenant == "" || a.Name == "" {
			continue
		}
		s.byKey[a.Tenant+"\x00"+a.Name] = a
	}
}

// SnapshotStore keeps the latest valid snapshot and swaps it atomically.
// A snapshot with a lower or equal registry_revision than the current one is
// rejected (F-5 §5.8: rollback requires a data-plane restart).
type SnapshotStore struct {
	mu      sync.RWMutex
	current *Snapshot
	source  string // file path or URL, for logging
}

// NewSnapshotStore creates an empty store. Until the first snapshot lands,
// Ready reports false and the data plane must fail closed.
func NewSnapshotStore() *SnapshotStore {
	return &SnapshotStore{}
}

// Current returns the latest snapshot (nil before the first load).
func (st *SnapshotStore) Current() *Snapshot {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.current
}

// Ready reports whether a snapshot is loaded.
func (st *SnapshotStore) Ready() bool {
	return st.Current() != nil
}

// Replace atomically installs snap when its registry_revision is strictly
// greater than the current one. Equal/lower revisions are refused so a stale
// control-plane replica cannot roll the data plane back.
func (st *SnapshotStore) Replace(snap *Snapshot) (bool, error) {
	if snap == nil {
		return false, fmt.Errorf("a2aproxy: nil snapshot")
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.current != nil && snap.RegistryRevision <= st.current.RegistryRevision {
		return false, nil
	}
	snap.reindex()
	st.current = snap
	return true, nil
}

// ForceReplace installs snap regardless of revision (startup/first load).
func (st *SnapshotStore) ForceReplace(snap *Snapshot) error {
	if snap == nil {
		return fmt.Errorf("a2aproxy: nil snapshot")
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	snap.reindex()
	st.current = snap
	return nil
}

// LoadFile reads and decodes a snapshot file. It is the dev-mode source.
func LoadFile(path string) (*Snapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("a2aproxy: read snapshot file: %w", err)
	}
	return DecodeSnapshot(raw)
}

// FetchSnapshot pulls the control-plane snapshot with If-None-Match.
// It returns (nil, nil) on 304 (no change).
func FetchSnapshot(url, token, etag string) (*Snapshot, string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("a2aproxy: build snapshot request: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := snapshotHTTPClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("a2aproxy: fetch snapshot: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, etag, nil
	case http.StatusOK:
	default:
		return nil, "", fmt.Errorf("a2aproxy: snapshot endpoint status %d", resp.StatusCode)
	}
	raw, err := readAllLimited(resp.Body, maxSnapshotBytes)
	if err != nil {
		return nil, "", err
	}
	snap, err := DecodeSnapshot(raw)
	if err != nil {
		return nil, "", err
	}
	return snap, resp.Header.Get("ETag"), nil
}

// maxSnapshotBytes caps the snapshot payload (agents × cards). 64 MiB is far
// above the MVP scale and guards against a misbehaving control plane.
const maxSnapshotBytes = 64 << 20

var snapshotHTTPClient = &http.Client{Timeout: 30 * time.Second}

// ParseAgentCard decodes the raw card carried by a snapshot agent. The data
// plane needs the parsed card for the frozen skill/tenant checks.
func (a *SnapshotAgent) ParseAgentCard() (*sdk.AgentCard, error) {
	var card sdk.AgentCard
	dec := json.NewDecoder(strings.NewReader(string(a.Card)))
	if err := dec.Decode(&card); err != nil {
		return nil, fmt.Errorf("a2aproxy: decode agent card: %w", err)
	}
	return &card, nil
}
