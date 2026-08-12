package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/GokturkFK/gokkalkan/internal/honeypot"
	"github.com/GokturkFK/gokkalkan/internal/proxy"
	"github.com/GokturkFK/gokturk-core/correlate"
	"github.com/GokturkFK/gokturk-core/trap"
	_ "github.com/lib/pq"
)

// setupStore, gercek bir Postgres'e baglanip semayi sifirdan kurar.
// DB erisilemezse test SKIP edilir (CI'da servis olarak ayakta).
//
// NOT: DB'ye karsi DROP/CREATE yapan testler BU pakette toplanir; ayri bir
// pakette tekrarlanirsa `go test ./...` paketleri es zamanli calistirdigi
// icin ayni Postgres uzerinde yaris olusur (GOKTURK'te yasandi).
func setupStore(t *testing.T) *Store {
	t.Helper()

	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dsn = "postgres://gokkalkan:gokkalkan@localhost:5432/gokkalkan?sslmode=disable"
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		skipOrFail(t, "postgres surucusu acilamadi: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		skipOrFail(t, "postgres erisilemez: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	for _, tbl := range []string{"trip_events", "alerts", "agent_allowlist", "agents", "honeypot_tools"} {
		if _, err := db.Exec("DROP TABLE IF EXISTS " + tbl + " CASCADE"); err != nil {
			t.Fatalf("%s dusurulemedi: %v", tbl, err)
		}
	}
	applySchema(t, db)
	return New(db)
}

// skipOrFail, yerelde (DB yokken) testi atlar ama CI'da PATLATIR.
//
// Gerekce: bu paketteki testler enforcement zincirinin tek gercek
// dogrulamasi. Sessizce atlanirlarsa CI yesil gorunur, kapsam kapisi de
// yaniltir — GOKTURK'te "postgres erisilemez" hatasinin aslinda yanlis
// sifre demek oldugu ve testlerin sessizce SKIP oldugu bir durum yasandi.
// CI'da bu asla kabul edilmemeli.
func skipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("CI") != "" {
		t.Fatalf("CI'da DB zorunlu — "+format, args...)
	}
	t.Skipf(format+" (yerelde atlaniyor)", args...)
}

// applySchema, migrations/*.sql dosyalarinin Up bolumlerini sirayla uygular.
func applySchema(t *testing.T, db *sql.DB) {
	t.Helper()

	files, err := filepath.Glob(filepath.Join("..", "..", "migrations", "*.sql"))
	if err != nil {
		t.Fatalf("migration'lar bulunamadi: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("hic migration dosyasi yok")
	}
	sort.Strings(files)

	for _, f := range files {
		content, err := os.ReadFile(f) //nolint:gosec // test icinde sabit repo yolu
		if err != nil {
			t.Fatalf("%s okunamadi: %v", f, err)
		}
		up := extractUp(string(content))
		if strings.TrimSpace(up) == "" {
			continue
		}
		if _, err := db.Exec(up); err != nil {
			t.Fatalf("%s uygulanamadi: %v", f, err)
		}
	}
}

func extractUp(s string) string {
	_, after, found := strings.Cut(s, "-- +goose Up")
	if !found {
		return ""
	}
	before, _, found := strings.Cut(after, "-- +goose Down")
	if !found {
		return after
	}
	return before
}

func newAgent(t *testing.T, s *Store, name string) string {
	t.Helper()
	var id string
	err := s.db.QueryRow(
		`INSERT INTO agents (name, token_hash) VALUES ($1, $2) RETURNING id`,
		name, "hash-"+name).Scan(&id)
	if err != nil {
		t.Fatalf("agent olusturulamadi: %v", err)
	}
	return id
}

// --- proxy.Store ---

func TestAgentStatusAndAllowlist(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()
	id := newAgent(t, s, "ci-deploy-agent")

	st, err := s.AgentStatus(ctx, id)
	if err != nil {
		t.Fatalf("AgentStatus: %v", err)
	}
	if st.Revoked {
		t.Error("yeni agent revoked gorunuyor")
	}

	if _, err := s.db.Exec(
		`INSERT INTO agent_allowlist (agent_id, method, host, path_prefix) VALUES ($1,'GET','api.github.com','/repos')`,
		id); err != nil {
		t.Fatalf("allowlist eklenemedi: %v", err)
	}
	entries, err := s.Allowlist(ctx, id)
	if err != nil {
		t.Fatalf("Allowlist: %v", err)
	}
	if len(entries) != 1 || entries[0].Host != "api.github.com" || entries[0].PathPrefix != "/repos" {
		t.Fatalf("allowlist beklenmedik: %+v", entries)
	}
}

func TestAgentStatus_NotFound(t *testing.T) {
	s := setupStore(t)
	_, err := s.AgentStatus(context.Background(), "00000000-0000-0000-0000-000000000000")
	if !errors.Is(err, proxy.ErrAgentNotFound) {
		t.Fatalf("hata = %v, ErrAgentNotFound bekleniyordu", err)
	}
}

// Store, proxy.Enforcer ile GERCEKTEN calisiyor mu (arayuz uyumu + davranis).
func TestEnforcerWithRealStore(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()
	id := newAgent(t, s, "agent-enforcer")
	if _, err := s.db.Exec(
		`INSERT INTO agent_allowlist (agent_id, method, host, path_prefix) VALUES ($1,'*','api.github.com','/repos')`,
		id); err != nil {
		t.Fatal(err)
	}

	e := proxy.NewEnforcer(s)

	if d := e.Evaluate(ctx, proxy.Request{AgentID: id, Method: "GET", Host: "api.github.com", Path: "/repos/foo"}); !d.Allowed {
		t.Errorf("izinli cagri reddedildi: %s", d.Reason)
	}
	if d := e.Evaluate(ctx, proxy.Request{AgentID: id, Method: "GET", Host: "evil.example.com", Path: "/x"}); d.Allowed {
		t.Error("allowlist disi host'a izin verildi")
	}

	// Kesilen agent hicbir cagri yapamaz — enforcement'in kendisi.
	if err := s.RevokeAgent(ctx, id, time.Now()); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}
	if d := e.Evaluate(ctx, proxy.Request{AgentID: id, Method: "GET", Host: "api.github.com", Path: "/repos/foo"}); d.Allowed {
		t.Error("kesilmis agent'a izin verildi")
	}
}

func TestRevokeAgent_PreservesFirstRevocation(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()
	id := newAgent(t, s, "agent-revoke")

	first := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	if err := s.RevokeAgent(ctx, id, first); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAgent(ctx, id, first.Add(time.Hour)); err != nil {
		t.Fatalf("ikinci revoke hata verdi: %v", err)
	}

	var got time.Time
	if err := s.db.QueryRow(`SELECT revoked_at FROM agents WHERE id=$1`, id).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if !got.UTC().Equal(first) {
		t.Errorf("revoked_at = %v, ilk kesilme ani korunmaliydi (%v)", got.UTC(), first)
	}
}

func TestRevokeAgent_NotFound(t *testing.T) {
	s := setupStore(t)
	err := s.RevokeAgent(context.Background(), "00000000-0000-0000-0000-000000000000", time.Now())
	if !errors.Is(err, proxy.ErrAgentNotFound) {
		t.Fatalf("hata = %v, ErrAgentNotFound bekleniyordu", err)
	}
}

// --- honeypot.Store ---

func TestHoneypotCreateAndFind(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()

	tool := honeypot.Tool{
		ID:          "3f0e8f5e-1111-2222-3333-444444444444",
		Name:        "internal-billing-export",
		Description: "Exports billing records.",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		CreatedBy:   "soc",
		CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
	}
	if err := s.Create(ctx, tool); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.FindByName(ctx, tool.Name)
	if err != nil {
		t.Fatalf("FindByName: %v", err)
	}
	if got.ID != tool.ID || got.Description != tool.Description || got.CreatedBy != "soc" {
		t.Errorf("tool beklenmedik: %+v", got)
	}
	if got.RevokedAt != nil {
		t.Error("yeni tool revoked gorunuyor")
	}
}

// Mesru bir tool adi -> ErrToolNotFound -> Decoder bunu ErrNotATrip'e cevirir
// (sifir-FP zincirinin DB ayagi).
func TestHoneypotFindByName_NotFound(t *testing.T) {
	s := setupStore(t)
	_, err := s.FindByName(context.Background(), "github-search")
	if !errors.Is(err, honeypot.ErrToolNotFound) {
		t.Fatalf("hata = %v, ErrToolNotFound bekleniyordu", err)
	}
}

// --- trip_events ---

// GK-B1 event'i: trap_id gercek bir honeypot uuid'si.
func TestInsertTripEvent_Honeypot(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()

	toolID := "3f0e8f5e-aaaa-bbbb-cccc-dddddddddddd"
	if err := s.Create(ctx, honeypot.Tool{
		ID: toolID, Name: "internal-billing-export", Description: "x", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	ev := trap.TripEvent{
		EventID: "evt-hp", TrapID: toolID, Sensor: "mcp-proxy",
		Source: "agent-42", ObservedAt: time.Now().UTC(), Raw: json.RawMessage(`{"tool":"x"}`),
	}
	if err := s.InsertTripEvent(ctx, ev); err != nil {
		t.Fatalf("InsertTripEvent: %v", err)
	}

	var stored string
	if err := s.db.QueryRow(`SELECT trap_id::text FROM trip_events WHERE event_id='evt-hp'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != toolID {
		t.Errorf("trap_id = %q, istenen %q", stored, toolID)
	}
}

// GK-A2 event'i: ortada BIZIM tuzagimiz yok -> trap_id NULL yazilmali.
// Bu test, migrations/00004'un cozdugu somut hatanin regresyon testidir:
// oncesinde `invalid input syntax for type uuid` ile patliyordu.
func TestInsertTripEvent_DetectionWithoutTrap(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()

	ev := trap.TripEvent{
		EventID: "evt-detect", TrapID: "", Sensor: "mcp-proxy",
		Source: "agent-1", ObservedAt: time.Now().UTC(),
		Raw: json.RawMessage(`{"tool_name":"helper-tool","matched_pattern":"ignore-previous-instructions"}`),
	}
	if err := s.InsertTripEvent(ctx, ev); err != nil {
		t.Fatalf("tuzak icermeyen tespit yazilamadi: %v", err)
	}

	var trapID sql.NullString
	var raw []byte
	if err := s.db.QueryRow(
		`SELECT trap_id::text, raw FROM trip_events WHERE event_id='evt-detect'`).Scan(&trapID, &raw); err != nil {
		t.Fatal(err)
	}
	if trapID.Valid {
		t.Errorf("trap_id = %q, NULL olmaliydi", trapID.String)
	}
	if !strings.Contains(string(raw), "helper-tool") {
		t.Errorf("tool adi raw'da kaybolmus: %s", raw)
	}
}

func TestInsertTripEvent_Idempotent(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()

	ev := trap.TripEvent{EventID: "dup", Sensor: "mcp-proxy", Source: "agent-1", ObservedAt: time.Now().UTC()}
	if err := s.InsertTripEvent(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertTripEvent(ctx, ev); err != nil {
		t.Fatalf("ikinci yazim hata verdi (idempotent olmaliydi): %v", err)
	}

	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM trip_events WHERE event_id='dup'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("satir sayisi = %d, istenen 1", n)
	}
}

func TestTripsBySource_WindowAndSource(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	events := []trap.TripEvent{
		{EventID: "in-1", Sensor: "p", Source: "agent-1", ObservedAt: now.Add(-time.Minute)},
		{EventID: "in-2", Sensor: "p", Source: "agent-1", ObservedAt: now.Add(-2 * time.Minute)},
		{EventID: "old", Sensor: "p", Source: "agent-1", ObservedAt: now.Add(-2 * time.Hour)},
		{EventID: "other", Sensor: "p", Source: "agent-2", ObservedAt: now},
	}
	for _, ev := range events {
		if err := s.InsertTripEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.TripsBySource(ctx, "agent-1", 30*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("trip sayisi = %d, istenen 2 (%+v)", len(got), got)
	}
	for _, ev := range got {
		if ev.Source != "agent-1" {
			t.Errorf("baska kaynak sizdi: %+v", ev)
		}
	}
}

// --- alerts ---

// Kampanya birlesmesi: ayni kaynak icin ikinci alarm YENI SATIR ACMAZ,
// mevcut acik alarmi Critical'a yukseltir.
func TestUpsertAlert_MergesBySource(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	high := correlate.Alert{
		Severity: correlate.SeverityHigh, Technique: honeypot.TechniqueToolInvocation,
		Source: "agent-1", Status: correlate.StatusOpen,
		FirstSeen: now.Add(-time.Minute), LastSeen: now.Add(-time.Minute), TripCount: 1,
	}
	id1, err := s.UpsertAlert(ctx, high)
	if err != nil {
		t.Fatal(err)
	}

	critical := high
	critical.Severity = correlate.SeverityCritical
	critical.LastSeen = now
	critical.TripCount = 2
	id2, err := s.UpsertAlert(ctx, critical)
	if err != nil {
		t.Fatal(err)
	}

	if id1 != id2 {
		t.Errorf("yeni alarm satiri acildi (%s -> %s), birlesmeliydi", id1, id2)
	}

	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM alerts WHERE source='agent-1'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("alarm satiri = %d, istenen 1", n)
	}

	alerts, err := s.Alerts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Severity != correlate.SeverityCritical || alerts[0].TripCount != 2 {
		t.Errorf("alarm beklenmedik: %+v", alerts)
	}
	if alerts[0].Technique != honeypot.TechniqueToolInvocation {
		t.Errorf("technique = %q", alerts[0].Technique)
	}
}
