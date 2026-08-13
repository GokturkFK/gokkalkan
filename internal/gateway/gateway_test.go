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

// Agent'lar proxy'ye ORIGIN-FORM istek gonderir (`GET /path` + `Host:`
// basligi); boyle bir istekte r.URL.Host BOSTUR. Yukaridaki testler
// httptest.NewRequest'i MUTLAK url ile kurdugu icin o alan dolu gelir ve
// gercek kullanimda olmayan bir kolayligi test eder.
//
// Bu test gercek bir dinleyici + gercek bir istemci kullanir: eskiden
// ReverseProxy "http: no Host in request URL" ile 502 donuyordu, yani
// DoD madde 3 ("mesru cagri engelsiz gecer") fiilen calismiyordu.
func TestServeHTTP_AllowedCallForwardsOverRealListener(t *testing.T) {
	rt := &fakeRoundTripper{}
	h, err := New(testMediator(t, true), &fakeEnforce{}, func() string { return "evt-real" }, nil, rt, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(h)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/repos/octocat/hello-world", nil)
	if err != nil {
		t.Fatal(err)
	}
	// curl -H "Host: api.github.com" ile ayni: hedef Host basligindan gelir.
	req.Host = "api.github.com"
	req.Header.Set(transport.HeaderAgentID, "agent-1")

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mesru cagri status = %d, istenen %d", resp.StatusCode, http.StatusOK)
	}
	if !rt.called {
		t.Fatal("mesru cagri gercek hedefe iletilmedi")
	}
	if got := rt.req.URL.Host; got != "api.github.com" {
		t.Errorf("iletilen URL.Host = %q, istenen %q", got, "api.github.com")
	}
	if got := rt.req.URL.Path; got != "/repos/octocat/hello-world" {
		t.Errorf("iletilen path = %q", got)
	}
	if got := rt.req.URL.Scheme; got != "https" {
		t.Errorf("iletilen sema = %q, istenen https", got)
	}
}

// Hedef, istekten yeniden cikarilmamali: allowlist kararini gecen kanonik
// host neyse iletme de oraya gitmeli. Aksi halde karar bir degere, iletme
// baska bir degere bakardi (parser-differential).
func TestServeHTTP_ForwardsToValidatedHostNotRawRequest(t *testing.T) {
	rt := &fakeRoundTripper{}
	h, err := New(testMediator(t, true), &fakeEnforce{}, func() string { return "evt-canon" }, nil, rt, testLogger())
	if err != nil {
		t.Fatal(err)
	}

	// Ham istekte port var ve path kanonik degil; mediator/transport bunu
	// "api.github.com" + "/repos/foo" olarak dogrular.
	r := httptest.NewRequest(http.MethodGet, "http://api.github.com:443/repos/./foo", nil)
	r.Header.Set(transport.HeaderAgentID, "agent-1")

	h.ServeHTTP(httptest.NewRecorder(), r)

	if !rt.called {
		t.Fatal("cagri iletilmedi")
	}
	if got := rt.req.URL.Host; got != "api.github.com" {
		t.Errorf("iletilen host = %q, istenen dogrulanan kanonik deger", got)
	}
	if got := rt.req.URL.Path; got != "/repos/foo" {
		t.Errorf("iletilen path = %q, istenen kanonik /repos/foo", got)
	}
	if got := rt.req.Host; got != "api.github.com" {
		t.Errorf("upstream'e giden Host basligi = %q", got)
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
