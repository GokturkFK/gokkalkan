package proxy

import (
	"context"
	"errors"
	"testing"
)

type fakeStore struct {
	statuses   map[string]AgentStatus
	allowlists map[string][]AllowlistEntry
	statusErr  error
	listErr    error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		statuses:   make(map[string]AgentStatus),
		allowlists: make(map[string][]AllowlistEntry),
	}
}

func (s *fakeStore) AgentStatus(_ context.Context, agentID string) (*AgentStatus, error) {
	if s.statusErr != nil {
		return nil, s.statusErr
	}
	st, ok := s.statuses[agentID]
	if !ok {
		return nil, ErrAgentNotFound
	}
	return &st, nil
}

func (s *fakeStore) Allowlist(_ context.Context, agentID string) ([]AllowlistEntry, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.allowlists[agentID], nil
}

func TestEvaluate_AllowedCall(t *testing.T) {
	store := newFakeStore()
	store.statuses["agent-1"] = AgentStatus{Revoked: false}
	store.allowlists["agent-1"] = []AllowlistEntry{{Method: "GET", Host: "api.github.com", PathPrefix: "/repos"}}

	e := NewEnforcer(store)
	d := e.Evaluate(context.Background(), Request{AgentID: "agent-1", Method: "GET", Host: "api.github.com", Path: "/repos/foo/bar"})

	if !d.Allowed {
		t.Errorf("izinli cagri reddedildi: %+v", d)
	}
}

func TestEvaluate_UnknownEndpointDenied(t *testing.T) {
	store := newFakeStore()
	store.statuses["agent-1"] = AgentStatus{Revoked: false}
	store.allowlists["agent-1"] = []AllowlistEntry{{Method: "GET", Host: "api.github.com", PathPrefix: "/repos"}}

	e := NewEnforcer(store)
	d := e.Evaluate(context.Background(), Request{AgentID: "agent-1", Method: "GET", Host: "evil.example.com", Path: "/steal"})

	if d.Allowed {
		t.Error("allowlist disi endpoint'e izin verildi")
	}
}

func TestEvaluate_EmptyAllowlistDeniesEverything(t *testing.T) {
	store := newFakeStore()
	store.statuses["agent-1"] = AgentStatus{Revoked: false}

	e := NewEnforcer(store)
	d := e.Evaluate(context.Background(), Request{AgentID: "agent-1", Method: "GET", Host: "anywhere.com", Path: "/"})

	if d.Allowed {
		t.Error("bos allowlist ile cagriya izin verildi (deny-by-default ihlali)")
	}
}

func TestEvaluate_UnknownAgentDenied(t *testing.T) {
	store := newFakeStore()

	e := NewEnforcer(store)
	d := e.Evaluate(context.Background(), Request{AgentID: "ghost-agent", Method: "GET", Host: "api.github.com", Path: "/repos"})

	if d.Allowed {
		t.Error("bilinmeyen agent icin izin verildi")
	}
}

func TestEvaluate_RevokedAgentDenied(t *testing.T) {
	store := newFakeStore()
	store.statuses["agent-1"] = AgentStatus{Revoked: true}
	store.allowlists["agent-1"] = []AllowlistEntry{{Method: "*", Host: "api.github.com", PathPrefix: "/"}}

	e := NewEnforcer(store)
	d := e.Evaluate(context.Background(), Request{AgentID: "agent-1", Method: "GET", Host: "api.github.com", Path: "/repos"})

	if d.Allowed {
		t.Error("revoked agent icin izin verildi")
	}
}

func TestEvaluate_StoreErrorDenies(t *testing.T) {
	store := newFakeStore()
	store.statusErr = errors.New("db down")

	e := NewEnforcer(store)
	d := e.Evaluate(context.Background(), Request{AgentID: "agent-1", Method: "GET", Host: "api.github.com", Path: "/repos"})

	if d.Allowed {
		t.Error("store hatasinda izin verildi (emin olunmayan durumda reddet ilkesi ihlal edildi)")
	}
}

func TestEvaluate_WildcardMethodMatches(t *testing.T) {
	store := newFakeStore()
	store.statuses["agent-1"] = AgentStatus{}
	store.allowlists["agent-1"] = []AllowlistEntry{{Method: "*", Host: "api.github.com", PathPrefix: "/"}}

	e := NewEnforcer(store)
	for _, method := range []string{"GET", "POST", "DELETE"} {
		d := e.Evaluate(context.Background(), Request{AgentID: "agent-1", Method: method, Host: "api.github.com", Path: "/anything"})
		if !d.Allowed {
			t.Errorf("wildcard method %q reddedildi: %+v", method, d)
		}
	}
}

func TestEvaluate_WrongMethodDenied(t *testing.T) {
	store := newFakeStore()
	store.statuses["agent-1"] = AgentStatus{}
	store.allowlists["agent-1"] = []AllowlistEntry{{Method: "GET", Host: "api.github.com", PathPrefix: "/repos"}}

	e := NewEnforcer(store)
	d := e.Evaluate(context.Background(), Request{AgentID: "agent-1", Method: "DELETE", Host: "api.github.com", Path: "/repos/foo"})

	if d.Allowed {
		t.Error("izinli olmayan method ile cagriya izin verildi")
	}
}

func TestEvaluate_PathPrefixBoundary(t *testing.T) {
	store := newFakeStore()
	store.statuses["agent-1"] = AgentStatus{}
	store.allowlists["agent-1"] = []AllowlistEntry{{Method: "*", Host: "api.github.com", PathPrefix: "/repos"}}

	e := NewEnforcer(store)

	d := e.Evaluate(context.Background(), Request{AgentID: "agent-1", Method: "GET", Host: "api.github.com", Path: "/other"})
	if d.Allowed {
		t.Error("prefix disi yola izin verildi")
	}

	d = e.Evaluate(context.Background(), Request{AgentID: "agent-1", Method: "GET", Host: "api.github.com", Path: "/repos"})
	if !d.Allowed {
		t.Error("prefix ile tam eslesen yol reddedildi")
	}

	d = e.Evaluate(context.Background(), Request{AgentID: "agent-1", Method: "GET", Host: "api.github.com", Path: "/repos/foo"})
	if !d.Allowed {
		t.Error("prefix altindaki alt yol reddedildi")
	}
}

// "/repos" izni "/repository" gibi yaninda baska bir kelime devam eden
// yollara sizmamali — sadece segment sinirinda (/repos veya /repos/...)
// eslesme kabul edilmeli. Duz string prefix karsilastirmasi bunu kacirirdi.
func TestEvaluate_PathPrefixDoesNotLeakToSiblingSegment(t *testing.T) {
	store := newFakeStore()
	store.statuses["agent-1"] = AgentStatus{}
	store.allowlists["agent-1"] = []AllowlistEntry{{Method: "*", Host: "api.github.com", PathPrefix: "/repos"}}

	e := NewEnforcer(store)
	d := e.Evaluate(context.Background(), Request{AgentID: "agent-1", Method: "GET", Host: "api.github.com", Path: "/repository-secrets"})

	if d.Allowed {
		t.Error("komsu segment'e (/repository-secrets) allowlist-bypass ile izin verildi")
	}
}

// "/repos/../../secrets" gibi normalize edilmemis bir yol, path.Clean
// uygulanmadan prefix kontrolunu atlatabilirdi (path-traversal).
func TestEvaluate_PathTraversalNormalizedBeforeMatch(t *testing.T) {
	store := newFakeStore()
	store.statuses["agent-1"] = AgentStatus{}
	store.allowlists["agent-1"] = []AllowlistEntry{{Method: "*", Host: "api.github.com", PathPrefix: "/repos"}}

	e := NewEnforcer(store)
	d := e.Evaluate(context.Background(), Request{AgentID: "agent-1", Method: "GET", Host: "api.github.com", Path: "/repos/../../secrets"})

	if d.Allowed {
		t.Error("path-traversal ile normalize edilince prefix disina cikan yola izin verildi")
	}
}

// Host/Method karsilastirmasi case-insensitive olmali; aksi halde
// "Api.Github.Com" gibi bir case varyasyonu deny-by-default'u yanlislikla
// tetikleyip meslu cagriyi da engelleyebilir (sifir-FP ihlali).
func TestEvaluate_HostAndMethodCaseInsensitive(t *testing.T) {
	store := newFakeStore()
	store.statuses["agent-1"] = AgentStatus{}
	store.allowlists["agent-1"] = []AllowlistEntry{{Method: "get", Host: "API.GITHUB.COM", PathPrefix: "/repos"}}

	e := NewEnforcer(store)
	d := e.Evaluate(context.Background(), Request{AgentID: "agent-1", Method: "GET", Host: "api.github.com", Path: "/repos/foo"})

	if !d.Allowed {
		t.Error("case farkli ama esdeger host/method reddedildi")
	}
}

func TestEvaluate_MultipleEntriesFirstNoMatchSecondMatches(t *testing.T) {
	store := newFakeStore()
	store.statuses["agent-1"] = AgentStatus{}
	store.allowlists["agent-1"] = []AllowlistEntry{
		{Method: "GET", Host: "other.com", PathPrefix: "/"},
		{Method: "POST", Host: "api.github.com", PathPrefix: "/issues"},
	}

	e := NewEnforcer(store)
	d := e.Evaluate(context.Background(), Request{AgentID: "agent-1", Method: "POST", Host: "api.github.com", Path: "/issues/1/comments"})

	if !d.Allowed {
		t.Errorf("ikinci girdiyle eslesen cagri reddedildi: %+v", d)
	}
}
