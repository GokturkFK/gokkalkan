package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/GokturkFK/gokkalkan/internal/enforce"
	"github.com/GokturkFK/gokkalkan/internal/mediator"
	"github.com/GokturkFK/gokkalkan/internal/proxy"
	"github.com/GokturkFK/gokkalkan/internal/receipt"
	"github.com/GokturkFK/gokkalkan/internal/transport"
	"github.com/GokturkFK/gokturk-core/trap"
)

const seed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

type fakeEval struct{ allow bool }

func (f fakeEval) Evaluate(_ context.Context, _ proxy.Request) proxy.Decision {
	if f.allow {
		return proxy.Decision{Allowed: true, Reason: "allowlist eslesmesi"}
	}
	return proxy.Decision{Allowed: false, Reason: "allowlist'te esleseme yok (deny-by-default)"}
}

type fakeReceiptStore struct{}

func (fakeReceiptStore) InsertReceipt(_ context.Context, _ receipt.SignedReceipt) (string, error) {
	return "rcp-1", nil
}

type fakeEnforce struct {
	calls []trap.TripEvent
	err   error
}

// fakeRoundTripper, gercek DNS/network'e cikmadan izinli cagrinin
// httputil.ReverseProxy'ye kadar dogru ilerledigini dogrulamak icin
// kullanilir.
type fakeRoundTripper struct {
	called bool
	req    *http.Request
}

func (f *fakeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	f.called = true
	f.req = r
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
		Header:     make(http.Header),
	}, nil
}

func (f *fakeEnforce) Handle(_ context.Context, ev trap.TripEvent, _ string) (enforce.Result, error) {
	f.calls = append(f.calls, ev)
	if f.err != nil {
		return enforce.Result{}, f.err
	}
	return enforce.Result{}, nil
}

func testMediator(t *testing.T, allow bool) *mediator.Mediator {
	t.Helper()
	signer, err := receipt.NewSignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return mediator.New(fakeEval{allow: allow}, signer, fakeReceiptStore{}, nil)
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

func newReq(agentID string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://gateway.local/repos/foo", nil)
	if agentID != "" {
		r.Header.Set(transport.HeaderAgentID, agentID)
	}
	return r
}

func TestServeHTTP_AllowedCallForwardsAndDoesNotTriggerEnforce(t *testing.T) {
	eng := &fakeEnforce{}
	rt := &fakeRoundTripper{}
	h, err := New(testMediator(t, true), eng, func() string { return "evt-1" }, nil, rt, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, newReq("agent-1"))

	if !rt.called {
		t.Error("izinli cagri gercek hedefe iletilmedi")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, istenen %d", w.Code, http.StatusOK)
	}
	if len(eng.calls) != 0 {
		t.Errorf("izinli cagri enforce'u tetikledi: %+v", eng.calls)
	}
}

func TestServeHTTP_DeniedCallTriggersEnforceWithTripEvent(t *testing.T) {
	eng := &fakeEnforce{}
	h, err := New(testMediator(t, false), eng, func() string { return "evt-2" }, fixedTime, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, newReq("agent-1"))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, istenen %d", w.Code, http.StatusForbidden)
	}
	if len(eng.calls) != 1 {
		t.Fatalf("enforce 1 kez cagrilmaliydi, cagrildi: %d", len(eng.calls))
	}
	ev := eng.calls[0]
	if ev.EventID != "evt-2" || ev.Source != "agent-1" || ev.Sensor != "gateway" {
		t.Errorf("TripEvent alanlari beklenmedik: %+v", ev)
	}
	if !ev.ObservedAt.Equal(fixedTime()) {
		t.Errorf("ObservedAt = %v, istenen %v", ev.ObservedAt, fixedTime())
	}
}

func TestServeHTTP_EnforceErrorDoesNotChangeDenyResponse(t *testing.T) {
	eng := &fakeEnforce{err: errors.New("db down")}
	h, err := New(testMediator(t, false), eng, func() string { return "evt-3" }, nil, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, newReq("agent-1"))

	// enforce basarisiz olsa bile deny karari degismemeli (fail-closed
	// zaten verildi, korelasyon altyapisinin gecici arizasi bunu geri
	// almamali).
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, istenen %d", w.Code, http.StatusForbidden)
	}
}

func TestNew_MissingIDFuncRejected(t *testing.T) {
	_, err := New(testMediator(t, true), &fakeEnforce{}, nil, nil, nil, testLogger())
	if !errors.Is(err, ErrMissingIDFunc) {
		t.Fatalf("ErrMissingIDFunc bekleniyordu, geldi: %v", err)
	}
}

func fixedTime() time.Time {
	return time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
}
