// Package enforce, GKO-2: deception sinyalini AKSIYONA çevirir.
//
// GÖKTÜRK'te korelasyon yalnızca alarm üretiyordu; GÖKKALKAN'ın tezi
// (PROJECT_PLAN.md EPIC GK-C) alarmın aynı düzlemde bir kesme kararına
// dönüşmesi: tuzak tetiklenince saldırgan agent'ın dış çağrıları durur.
//
// Akış: TripEvent → kalıcı yaz → penceredeki trip'leri topla →
// gokturk-core/correlate.Evaluate → alarmı yaz → Critical ise agent'ı kes.
//
// Korelasyon mantığı bilinçli olarak burada DEĞİL: core'daki deterministik
// Evaluate kullanılır (tek trip → High, aynı kaynaktan ≥2 → tek Critical).
// Bu paket yalnızca onu besleyip sonucunu uygular.
package enforce

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/GokturkFK/gokkalkan/internal/proxy"
	"github.com/GokturkFK/gokturk-core/correlate"
	"github.com/GokturkFK/gokturk-core/trap"
)

// DefaultWindow, korelasyon penceresidir. Pencereyi seçmek çağıranın işidir
// (core sözleşmesi); GÖKTÜRK'teki değerle hizalı tutuldu.
const DefaultWindow = 30 * time.Minute

// Store, enforcement için gereken kalıcılık işlemlerini soyutlar.
// Gerçek implementasyon: internal/store.
type Store interface {
	InsertTripEvent(ctx context.Context, ev trap.TripEvent) error
	TripsBySource(ctx context.Context, source string, window time.Duration, now time.Time) ([]trap.TripEvent, error)
	UpsertAlert(ctx context.Context, a correlate.Alert) (string, error)
	RevokeAgent(ctx context.Context, agentID string, at time.Time) error
}

// Result, tek bir TripEvent'in işlenmesinin sonucudur.
type Result struct {
	Alerts []correlate.Alert
	// AgentRevoked, Critical alarm nedeniyle agent'ın fiilen kesildiğini
	// belirtir.
	AgentRevoked bool
	// RevokeErr, kesme denendi ama başarısız olduysa doludur. Alarm yine de
	// kaydedilmiştir; çağıran bunu görünür kılmalıdır (kesilemeyen bir
	// agent sessizce geçilmemeli).
	RevokeErr error
}

// Engine, TripEvent'leri işleyip enforcement uygular.
type Engine struct {
	store  Store
	window time.Duration
	now    func() time.Time
	logger *slog.Logger
}

// Option, Engine davranışını değiştiren opsiyonel ayardır.
type Option func(*Engine)

// WithWindow, korelasyon penceresini değiştirir.
func WithWindow(d time.Duration) Option { return func(e *Engine) { e.window = d } }

// WithClock, zaman kaynağını değiştirir (testler için).
func WithClock(now func() time.Time) Option { return func(e *Engine) { e.now = now } }

// New, verilen Store ile bir Engine kurar.
func New(store Store, logger *slog.Logger, opts ...Option) *Engine {
	e := &Engine{store: store, window: DefaultWindow, now: time.Now, logger: logger}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Handle, bir TripEvent'i işler.
//
// technique, alarma yazılacak ATLAS teknik kodudur ve çağıran tarafından
// verilir: honeypot.TechniqueToolInvocation (AML.T0053) veya
// detect.TechniqueToolPoisoning (AML.T0110.000). İki senaryo farklı
// adversary davranışını temsil ettiği için tek sabit kullanılmaz
// (docs/DECISIONS.md Karar 1).
func (e *Engine) Handle(ctx context.Context, ev trap.TripEvent, technique string) (Result, error) {
	if ev.Source == "" {
		return Result{}, errors.New("enforce: TripEvent.Source bos, korelasyon yapilamaz")
	}

	if err := e.store.InsertTripEvent(ctx, ev); err != nil {
		return Result{}, fmt.Errorf("enforce: trip kaydedilemedi: %w", err)
	}

	now := e.now()
	trips, err := e.store.TripsBySource(ctx, ev.Source, e.window, now)
	if err != nil {
		return Result{}, fmt.Errorf("enforce: trip'ler alinamadi: %w", err)
	}

	alerts := correlate.Evaluate(trips, technique)
	res := Result{Alerts: alerts}

	critical := false
	for i := range alerts {
		id, err := e.store.UpsertAlert(ctx, alerts[i])
		if err != nil {
			return res, fmt.Errorf("enforce: alarm yazilamadi: %w", err)
		}
		alerts[i].ID = id
		if alerts[i].Severity == correlate.SeverityCritical {
			critical = true
		}
	}

	if !critical {
		return res, nil
	}

	// Critical → agent'i kes. Bu, GOKKALKAN'i GOKTURK'ten ayiran adim:
	// alarm degil, aksiyon.
	if err := e.store.RevokeAgent(ctx, ev.Source, now); err != nil {
		res.RevokeErr = err
		if errors.Is(err, proxy.ErrAgentNotFound) {
			// Kayitli olmayan bir kaynaktan trip gelmis olabilir; alarm
			// yine de gecerli, ama kesilecek bir agent yok.
			e.logger.Warn("critical alarm var ama agent kayitli degil, kesilemedi",
				"source", ev.Source, "technique", technique)
			return res, nil
		}
		e.logger.Error("critical alarm var ama agent KESILEMEDI",
			"source", ev.Source, "technique", technique, "err", err)
		return res, nil
	}

	res.AgentRevoked = true
	e.logger.Warn("agent kesildi (critical alarm)",
		"source", ev.Source, "technique", technique)
	return res, nil
}
