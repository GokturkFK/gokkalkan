// Package store, GKO-2: GÖKKALKAN'ın Postgres kalıcılık katmanı.
//
// GK-A1 (proxy.Store) ve GK-B1 (honeypot.Store) bilerek arayüz arkasına
// soyutlanmıştı — "gerçek Postgres implementasyonu wiring aşamasının işi"
// (bkz. internal/proxy/proxy.go, internal/honeypot/honeypot.go paket
// yorumları). Bu paket o arayüzleri karşılar ve ek olarak trip_events /
// alerts kalıcılığını + agent revoke'unu sağlar.
//
// Şema: migrations/00001..00004.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/GokturkFK/gokkalkan/internal/honeypot"
	"github.com/GokturkFK/gokkalkan/internal/proxy"
	"github.com/GokturkFK/gokturk-core/correlate"
	"github.com/GokturkFK/gokturk-core/trap"
)

// Store, Postgres üzerinde çalışan kalıcılık katmanıdır.
type Store struct {
	db *sql.DB
}

// New, verilen açık *sql.DB ile bir Store kurar.
func New(db *sql.DB) *Store { return &Store{db: db} }

// --- proxy.Store ---

// AgentStatus, enforcement için agent'ın durumunu döner.
// Agent yoksa proxy.ErrAgentNotFound döner; Enforcer bunu (diğer tüm
// hatalar gibi) deny olarak yorumlar — deny-by-default.
func (s *Store) AgentStatus(ctx context.Context, agentID string) (*proxy.AgentStatus, error) {
	var revokedAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT revoked_at FROM agents WHERE id = $1`, agentID,
	).Scan(&revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, proxy.ErrAgentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: agent durumu okunamadi: %w", err)
	}
	return &proxy.AgentStatus{Revoked: revokedAt.Valid}, nil
}

// Allowlist, agent'ın izinli çağrı desenlerini döner.
func (s *Store) Allowlist(ctx context.Context, agentID string) ([]proxy.AllowlistEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT method, host, path_prefix FROM agent_allowlist WHERE agent_id = $1`, agentID)
	if err != nil {
		return nil, fmt.Errorf("store: allowlist okunamadi: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []proxy.AllowlistEntry
	for rows.Next() {
		var e proxy.AllowlistEntry
		if err := rows.Scan(&e.Method, &e.Host, &e.PathPrefix); err != nil {
			return nil, fmt.Errorf("store: allowlist satiri okunamadi: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: allowlist iterasyonu: %w", err)
	}
	return out, nil
}

// --- honeypot.Store ---

// Create, provision edilen sahte MCP tool'u honeypot_tools'a yazar.
func (s *Store) Create(ctx context.Context, t honeypot.Tool) error {
	schema := t.InputSchema
	if len(schema) == 0 {
		schema = []byte(`{}`)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO honeypot_tools (id, name, description, input_schema, created_by, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		t.ID, t.Name, t.Description, []byte(schema), nullString(t.CreatedBy), t.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: honeypot tool yazilamadi: %w", err)
	}
	return nil
}

// FindByName, agent'ın çağırdığı ada karşılık gelen tuzağı bulur.
// Bulunamazsa honeypot.ErrToolNotFound döner — Decoder bunu ErrNotATrip'e
// çevirir, yani meşru tool çağrıları hiçbir event üretmez (sıfır-FP).
func (s *Store) FindByName(ctx context.Context, name string) (*honeypot.Tool, error) {
	var (
		t         honeypot.Tool
		createdBy sql.NullString
		revokedAt sql.NullTime
		schema    []byte
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, description, input_schema, created_by, created_at, revoked_at
		 FROM honeypot_tools WHERE name = $1`, name,
	).Scan(&t.ID, &t.Name, &t.Description, &schema, &createdBy, &t.CreatedAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, honeypot.ErrToolNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: honeypot tool okunamadi: %w", err)
	}

	t.InputSchema = schema
	if createdBy.Valid {
		t.CreatedBy = createdBy.String
	}
	if revokedAt.Valid {
		rt := revokedAt.Time
		t.RevokedAt = &rt
	}
	return &t, nil
}

// --- trip_events ---

// InsertTripEvent, bir TripEvent'i idempotent yazar (event_id UNIQUE;
// aynı event tekrar gelirse sessizce yoksayılır — GÖKTÜRK APP-6'daki
// idempotency disiplininin aynısı).
//
// TrapID boşsa NULL yazılır: tuzak içermeyen tespitler (GK-A2, zehirli
// tool açıklaması) için ortada bizim bir tuzağımız yoktur. Bkz.
// migrations/00004 ve internal/detect/decoder.go.
func (s *Store) InsertTripEvent(ctx context.Context, ev trap.TripEvent) error {
	raw := ev.Raw
	if len(raw) == 0 {
		raw = []byte(`{}`)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO trip_events (event_id, trap_id, sensor, source, observed_at, raw)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (event_id) DO NOTHING`,
		ev.EventID, nullString(ev.TrapID), ev.Sensor, ev.Source, ev.ObservedAt, []byte(raw))
	if err != nil {
		return fmt.Errorf("store: trip event yazilamadi: %w", err)
	}
	return nil
}

// TripsBySource, verilen kaynak (agent) için son `window` süresindeki
// trip'leri döner. Korelasyon penceresini seçmek çağıranın işidir
// (gokturk-core/correlate paket sözleşmesi).
func (s *Store) TripsBySource(ctx context.Context, source string, window time.Duration, now time.Time) ([]trap.TripEvent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT event_id, COALESCE(trap_id::text, ''), sensor, source, observed_at, raw
		 FROM trip_events
		 WHERE source = $1 AND observed_at >= $2
		 ORDER BY observed_at`,
		source, now.Add(-window))
	if err != nil {
		return nil, fmt.Errorf("store: trip'ler okunamadi: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []trap.TripEvent
	for rows.Next() {
		var (
			ev  trap.TripEvent
			raw []byte
		)
		if err := rows.Scan(&ev.EventID, &ev.TrapID, &ev.Sensor, &ev.Source, &ev.ObservedAt, &raw); err != nil {
			return nil, fmt.Errorf("store: trip satiri okunamadi: %w", err)
		}
		ev.Raw = raw
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: trip iterasyonu: %w", err)
	}
	return out, nil
}

// --- alerts ---

// UpsertAlert, bir kaynak için alarmı yazar veya günceller.
//
// Kampanya birleşmesi (aynı kaynaktan 2. trip → tek Critical) ancak alarm
// kaynak başına TEK satır kalırsa görünür; bu yüzden açık bir alarm varsa
// severity/last_seen/trip_count güncellenir, yeni satır açılmaz.
// Döndürülen id, trip_events.alert_id'yi bağlamak için kullanılır.
func (s *Store) UpsertAlert(ctx context.Context, a correlate.Alert) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		`UPDATE alerts
		    SET severity = $1, technique = $2, last_seen = $3, trip_count = $4, updated_at = now()
		  WHERE source = $5 AND status = $6
		 RETURNING id`,
		a.Severity, nullString(a.Technique), a.LastSeen, a.TripCount, a.Source, correlate.StatusOpen,
	).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("store: alarm guncellenemedi: %w", err)
	}

	err = s.db.QueryRowContext(ctx,
		`INSERT INTO alerts (severity, technique, source, status, first_seen, last_seen, trip_count)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		a.Severity, nullString(a.Technique), a.Source, correlate.StatusOpen, a.FirstSeen, a.LastSeen, a.TripCount,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("store: alarm yazilamadi: %w", err)
	}
	return id, nil
}

// Alerts, panele beslenmek üzere alarmları en yeni önce döner (GKO-4).
func (s *Store) Alerts(ctx context.Context, limit int) ([]correlate.Alert, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, severity, COALESCE(technique, ''), source, status, first_seen, last_seen, trip_count
		 FROM alerts ORDER BY last_seen DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: alarmlar okunamadi: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []correlate.Alert
	for rows.Next() {
		var a correlate.Alert
		if err := rows.Scan(&a.ID, &a.Severity, &a.Technique, &a.Source, &a.Status,
			&a.FirstSeen, &a.LastSeen, &a.TripCount); err != nil {
			return nil, fmt.Errorf("store: alarm satiri okunamadi: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: alarm iterasyonu: %w", err)
	}
	return out, nil
}

// --- enforcement ---

// RevokeAgent, agent'ı keser (agents.revoked_at doldurulur). Proxy her
// istekte bu alanı kontrol eder, yani bu çağrı fiilen "bu agent'ın tüm dış
// çağrılarını durdur" demektir.
//
// Zaten kesilmiş bir agent'ta revoked_at KORUNUR (ilk kesilme anı kanıttır,
// tekrar tetiklenen alarmlar onu ileri kaydırmamalı). Etkilenen satır
// yoksa agent bulunamamıştır.
func (s *Store) RevokeAgent(ctx context.Context, agentID string, at time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE agents SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL`, at, agentID)
	if err != nil {
		return fmt.Errorf("store: agent kesilemedi: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: etkilenen satir alinamadi: %w", err)
	}
	if n == 0 {
		// Ya agent yok ya da zaten kesilmis; ikisi de hata degil ama
		// cagiran ayirt edebilsin diye kontrol edilir.
		var exists bool
		if err := s.db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM agents WHERE id = $1)`, agentID).Scan(&exists); err != nil {
			return fmt.Errorf("store: agent varligi kontrol edilemedi: %w", err)
		}
		if !exists {
			return proxy.ErrAgentNotFound
		}
	}
	return nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
