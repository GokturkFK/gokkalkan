package enforce

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/GokturkFK/gokkalkan/internal/proxy"
	"github.com/GokturkFK/gokturk-core/correlate"
	"github.com/GokturkFK/gokturk-core/trap"
)

const testTechnique = "AML.T0053"

type fakeStore struct {
	trips     []trap.TripEvent
	alerts    []correlate.Alert
	revoked   map[string]time.Time
	revokeErr error
	insertErr error
	tripsErr  error
	upsertErr error
}

func newFakeStore() *fakeStore { return &fakeStore{revoked: map[string]time.Time{}} }

func (f *fakeStore) InsertTripEvent(_ context.Context, ev trap.TripEvent) error {
	if f.insertErr != nil {
		return f.insertErr
	}
	for _, t := range f.trips { // event_id idempotency
		if t.EventID == ev.EventID {
			return nil
		}
	}
	f.trips = append(f.trips, ev)
	return nil
}

func (f *fakeStore) TripsBySource(_ context.Context, source string, window time.Duration, now time.Time) ([]trap.TripEvent, error) {
	if f.tripsErr != nil {
		return nil, f.tripsErr
	}
	var out []trap.TripEvent
	for _, t := range f.trips {
		if t.Source == source && !t.ObservedAt.Before(now.Add(-window)) {
			out = append(out, t)
		}
	}
	return out, nil
}

func (f *fakeStore) UpsertAlert(_ context.Context, a correlate.Alert) (string, error) {
	if f.upsertErr != nil {
		return "", f.upsertErr
	}
	for i := range f.alerts {
		if f.alerts[i].Source == a.Source {
			f.alerts[i] = a
			return "alert-" + a.Source, nil
		}
	}
	f.alerts = append(f.alerts, a)
	return "alert-" + a.Source, nil
}

func (f *fakeStore) RevokeAgent(_ context.Context, agentID string, at time.Time) error {
	if f.revokeErr != nil {
		return f.revokeErr
	}
	if _, ok := f.revoked[agentID]; !ok {
		f.revoked[agentID] = at
	}
	return nil
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func tripAt(id, source string, at time.Time) trap.TripEvent {
	return trap.TripEvent{EventID: id, Sensor: "mcp-proxy", Source: source, ObservedAt: at}
}

// Tek trip -> High alarm, agent KESILMEZ.
func TestHandle_SingleTripHighNoRevoke(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	fs := newFakeStore()
	e := New(fs, quietLogger(), WithClock(func() time.Time { return now }))

	res, err := e.Handle(context.Background(), tripAt("e1", "agent-1", now), testTechnique)
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if len(res.Alerts) != 1 || res.Alerts[0].Severity != correlate.SeverityHigh {
		t.Fatalf("High alarm bekleniyordu: %+v", res.Alerts)
	}
	if res.AgentRevoked {
		t.Error("tek trip'te agent kesilmemeliydi")
	}
	if _, ok := fs.revoked["agent-1"]; ok {
		t.Error("store'da revoke cagrisi olmamaliydi")
	}
	if res.Alerts[0].Technique != testTechnique {
		t.Errorf("technique = %q, istenen %q", res.Alerts[0].Technique, testTechnique)
	}
}

// Ayni kaynaktan 2. trip -> tek Critical + agent KESILIR (GOKKALKAN'in tezi).
func TestHandle_SecondTripCriticalRevokesAgent(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	fs := newFakeStore()
	e := New(fs, quietLogger(), WithClock(func() time.Time { return now }))

	if _, err := e.Handle(context.Background(), tripAt("e1", "agent-1", now.Add(-time.Minute)), testTechnique); err != nil {
		t.Fatalf("ilk trip hatasi: %v", err)
	}
	res, err := e.Handle(context.Background(), tripAt("e2", "agent-1", now), testTechnique)
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}

	if len(res.Alerts) != 1 {
		t.Fatalf("tek alarm bekleniyordu (kampanya birlesmesi): %+v", res.Alerts)
	}
	if res.Alerts[0].Severity != correlate.SeverityCritical {
		t.Errorf("severity = %q, istenen Critical", res.Alerts[0].Severity)
	}
	if res.Alerts[0].TripCount != 2 {
		t.Errorf("trip_count = %d, istenen 2", res.Alerts[0].TripCount)
	}
	if !res.AgentRevoked {
		t.Error("Critical alarmda agent kesilmeliydi")
	}
	if _, ok := fs.revoked["agent-1"]; !ok {
		t.Error("store'da revoke cagrisi bekleniyordu")
	}
}

// Ayni event_id tekrar gelirse trip sayisi artmamali (idempotency).
func TestHandle_DuplicateEventIsIdempotent(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	fs := newFakeStore()
	e := New(fs, quietLogger(), WithClock(func() time.Time { return now }))

	ev := tripAt("dup", "agent-1", now)
	if _, err := e.Handle(context.Background(), ev, testTechnique); err != nil {
		t.Fatalf("ilk: %v", err)
	}
	res, err := e.Handle(context.Background(), ev, testTechnique)
	if err != nil {
		t.Fatalf("ikinci: %v", err)
	}
	if res.Alerts[0].Severity != correlate.SeverityHigh {
		t.Errorf("ayni event iki kez islendi, Critical'a yukseldi: %+v", res.Alerts[0])
	}
	if res.AgentRevoked {
		t.Error("tekrarlanan ayni event agent'i kesmemeliydi")
	}
}

// Pencere disindaki eski trip korelasyona girmemeli.
func TestHandle_OldTripOutsideWindowIgnored(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	fs := newFakeStore()
	e := New(fs, quietLogger(),
		WithClock(func() time.Time { return now }),
		WithWindow(10*time.Minute))

	// Pencerenin cok disinda
	fs.trips = append(fs.trips, tripAt("old", "agent-1", now.Add(-2*time.Hour)))

	res, err := e.Handle(context.Background(), tripAt("new", "agent-1", now), testTechnique)
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if res.Alerts[0].Severity != correlate.SeverityHigh {
		t.Errorf("eski trip pencereye girdi, severity = %q", res.Alerts[0].Severity)
	}
	if res.AgentRevoked {
		t.Error("agent kesilmemeliydi")
	}
}

// Farkli kaynaklar birbirinin alarmini Critical'a yukseltmemeli.
func TestHandle_DifferentSourcesDoNotMerge(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	fs := newFakeStore()
	e := New(fs, quietLogger(), WithClock(func() time.Time { return now }))

	if _, err := e.Handle(context.Background(), tripAt("a1", "agent-1", now), testTechnique); err != nil {
		t.Fatal(err)
	}
	res, err := e.Handle(context.Background(), tripAt("b1", "agent-2", now), testTechnique)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Alerts) != 1 || res.Alerts[0].Severity != correlate.SeverityHigh {
		t.Errorf("agent-2 icin tek High bekleniyordu: %+v", res.Alerts)
	}
	if res.AgentRevoked {
		t.Error("agent-2 kesilmemeliydi")
	}
}

// Agent kayitli degilse: alarm yine yazilir, kesme sessizce gecilmez.
func TestHandle_RevokeAgentNotFoundSurfaced(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	fs := newFakeStore()
	fs.revokeErr = proxy.ErrAgentNotFound
	e := New(fs, quietLogger(), WithClock(func() time.Time { return now }))

	_, _ = e.Handle(context.Background(), tripAt("e1", "agent-x", now.Add(-time.Minute)), testTechnique)
	res, err := e.Handle(context.Background(), tripAt("e2", "agent-x", now), testTechnique)
	if err != nil {
		t.Fatalf("kesme basarisiz olsa da Handle hata dondurmemeli: %v", err)
	}
	if res.AgentRevoked {
		t.Error("AgentRevoked true olmamaliydi")
	}
	if !errors.Is(res.RevokeErr, proxy.ErrAgentNotFound) {
		t.Errorf("RevokeErr = %v, ErrAgentNotFound bekleniyordu", res.RevokeErr)
	}
	if len(res.Alerts) != 1 || res.Alerts[0].Severity != correlate.SeverityCritical {
		t.Error("kesme basarisiz olsa da Critical alarm kaydedilmeliydi")
	}
}

func TestHandle_EmptySourceRejected(t *testing.T) {
	fs := newFakeStore()
	e := New(fs, quietLogger())
	if _, err := e.Handle(context.Background(), trap.TripEvent{EventID: "e"}, testTechnique); err == nil {
		t.Fatal("bos Source icin hata bekleniyordu")
	}
}

func TestHandle_StoreErrorsPropagate(t *testing.T) {
	now := time.Now()
	boom := errors.New("boom")

	cases := map[string]func(*fakeStore){
		"insert": func(f *fakeStore) { f.insertErr = boom },
		"trips":  func(f *fakeStore) { f.tripsErr = boom },
		"upsert": func(f *fakeStore) { f.upsertErr = boom },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			fs := newFakeStore()
			setup(fs)
			e := New(fs, quietLogger(), WithClock(func() time.Time { return now }))
			if _, err := e.Handle(context.Background(), tripAt("e1", "agent-1", now), testTechnique); !errors.Is(err, boom) {
				t.Fatalf("hata yayilmadi: %v", err)
			}
		})
	}
}
