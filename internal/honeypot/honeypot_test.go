package honeypot

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/GokturkFK/gokturk-core/trap"
)

type fakeStore struct {
	tools map[string]Tool
}

func newFakeStore() *fakeStore {
	return &fakeStore{tools: make(map[string]Tool)}
}

func (s *fakeStore) Create(_ context.Context, t Tool) error {
	s.tools[t.Name] = t
	return nil
}

func (s *fakeStore) FindByName(_ context.Context, name string) (*Tool, error) {
	t, ok := s.tools[name]
	if !ok {
		return nil, ErrToolNotFound
	}
	return &t, nil
}

type fakeNames struct {
	name, description string
	schema            json.RawMessage
}

func (f fakeNames) Generate() (string, string, json.RawMessage) {
	return f.name, f.description, f.schema
}

func fixedTime(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func fixedID(id string) func() string {
	return func() string { return id }
}

func TestProvider_Provision(t *testing.T) {
	store := newFakeStore()
	names := fakeNames{name: "internal-billing-export", description: "Ic faturalandirma disa aktarim araci", schema: json.RawMessage(`{}`)}
	when := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)

	p := NewProvider(store, names, fixedID("tool-1"), fixedTime(when))

	tr, artifacts, err := p.Provision(context.Background(), "fetihcakmak")
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if tr.ID != "tool-1" || tr.Type != TypeAgentHoneypot || tr.Username != "internal-billing-export" {
		t.Errorf("trap alanlari beklenmedik: %+v", tr)
	}
	if !tr.CreatedAt.Equal(when) {
		t.Errorf("CreatedAt = %v, istenen %v", tr.CreatedAt, when)
	}
	if artifacts == nil {
		t.Fatal("artifacts nil olmamali (bos struct donmeli)")
	}

	stored, err := store.FindByName(context.Background(), "internal-billing-export")
	if err != nil {
		t.Fatalf("store'a yazilmamis: %v", err)
	}
	if stored.CreatedBy != "fetihcakmak" {
		t.Errorf("CreatedBy = %q, istenen fetihcakmak", stored.CreatedBy)
	}
}

// SecretHash alanina karsilik gelen bir sizinti olmamali: Provision hicbir
// dogrudan secret uretmez, Artifacts bos doner.
func TestProvider_Provision_NoSecretLeak(t *testing.T) {
	store := newFakeStore()
	names := fakeNames{name: "x", description: "y", schema: json.RawMessage(`{}`)}
	p := NewProvider(store, names, fixedID("tool-2"), fixedTime(time.Now()))

	_, artifacts, err := p.Provision(context.Background(), "creator")
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if artifacts.Secret != "" || artifacts.Username != "" {
		t.Errorf("honeypot tool icin artifacts bos olmali, geldi: %+v", artifacts)
	}
}

func TestDecoder_Decode_TripDetected(t *testing.T) {
	store := newFakeStore()
	_ = store.Create(context.Background(), Tool{ID: "tool-3", Name: "internal-billing-export", CreatedAt: time.Now()})

	d := NewDecoder(store, fixedID("evt-1"))

	inv := Invocation{ToolName: "internal-billing-export", AgentID: "agent-42", ObservedAt: time.Date(2026, 8, 12, 11, 0, 0, 0, time.UTC)}
	line, _ := json.Marshal(inv)

	obs := trap.RawObservation{Sensor: "mcp-proxy", Source: "agent-42", Line: string(line), ObservedAt: inv.ObservedAt}

	ev, err := d.Decode(obs)
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if ev.EventID != "evt-1" || ev.TrapID != "tool-3" || ev.Source != "agent-42" || ev.Sensor != "mcp-proxy" {
		t.Errorf("TripEvent alanlari beklenmedik: %+v", ev)
	}
}

// Meslu bir tool cagrisi (honeypot_tools'ta karsiligi olmayan) hicbir event
// uretmemeli — sifir-FP tezinin kod duzeyindeki karsiligi (issue #4 AC).
func TestDecoder_Decode_LegitimateCallProducesNoEvent(t *testing.T) {
	store := newFakeStore()
	d := NewDecoder(store, fixedID("evt-2"))

	inv := Invocation{ToolName: "real-github-api-tool", AgentID: "agent-1", ObservedAt: time.Now()}
	line, _ := json.Marshal(inv)
	obs := trap.RawObservation{Sensor: "mcp-proxy", Line: string(line), ObservedAt: inv.ObservedAt}

	ev, err := d.Decode(obs)
	if !errors.Is(err, trap.ErrNotATrip) {
		t.Fatalf("ErrNotATrip bekleniyordu, geldi: %v", err)
	}
	if ev != nil {
		t.Errorf("event nil olmali, geldi: %+v", ev)
	}
}

func TestDecoder_Decode_RevokedToolProducesNoEvent(t *testing.T) {
	store := newFakeStore()
	revoked := time.Now()
	_ = store.Create(context.Background(), Tool{ID: "tool-4", Name: "old-tool", RevokedAt: &revoked})

	d := NewDecoder(store, fixedID("evt-3"))

	inv := Invocation{ToolName: "old-tool", AgentID: "agent-9", ObservedAt: time.Now()}
	line, _ := json.Marshal(inv)
	obs := trap.RawObservation{Sensor: "mcp-proxy", Line: string(line), ObservedAt: inv.ObservedAt}

	_, err := d.Decode(obs)
	if !errors.Is(err, trap.ErrNotATrip) {
		t.Fatalf("revoked tool icin ErrNotATrip bekleniyordu, geldi: %v", err)
	}
}

func TestDecoder_Decode_InvalidObservation(t *testing.T) {
	store := newFakeStore()
	d := NewDecoder(store, fixedID("evt-4"))

	obs := trap.RawObservation{Sensor: "mcp-proxy", Line: "not-json", ObservedAt: time.Now()}
	if _, err := d.Decode(obs); err == nil {
		t.Fatal("gecersiz gozlem icin hata bekleniyordu")
	}
}

// trap.Provider ve trap.Decoder arayuzlerini gercekten uyguladigimizi
// derleme zamaninda dogrular.
var (
	_ trap.Provider = (*Provider)(nil)
	_ trap.Decoder  = (*Decoder)(nil)
)
