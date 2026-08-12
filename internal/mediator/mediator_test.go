package mediator

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/GokturkFK/gokkalkan/internal/proxy"
	"github.com/GokturkFK/gokkalkan/internal/receipt"
	"github.com/GokturkFK/gokkalkan/internal/transport"
)

const seed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

type fakeEval struct{ allow bool }

func (f fakeEval) Evaluate(_ context.Context, _ proxy.Request) proxy.Decision {
	if f.allow {
		return proxy.Decision{Allowed: true, Reason: "allowlist eslesmesi"}
	}
	return proxy.Decision{Allowed: false, Reason: "allowlist'te esleseme yok (deny-by-default)"}
}

type fakeStore struct {
	saved []receipt.SignedReceipt
	err   error
}

func (f *fakeStore) InsertReceipt(_ context.Context, sr receipt.SignedReceipt) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.saved = append(f.saved, sr)
	return "rcp-stored", nil
}

type failingSigner struct{}

func (failingSigner) Sign(receipt.Receipt) (receipt.SignedReceipt, error) {
	return receipt.SignedReceipt{}, errors.New("hsm yok")
}

func newReq(t *testing.T, method, url, agentID string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, url, nil)
	if agentID != "" {
		r.Header.Set(transport.HeaderAgentID, agentID)
	}
	return r
}

func testSigner(t *testing.T) *receipt.Signer {
	t.Helper()
	s, err := receipt.NewSignerFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Izinli cagri: karar allow, receipt uretilir, imza dogrulanir.
func TestHandle_AllowedProducesVerifiableReceipt(t *testing.T) {
	sg := testSigner(t)
	st := &fakeStore{}
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	m := New(fakeEval{allow: true}, sg, st, func() time.Time { return now })

	res, err := m.Handle(context.Background(), newReq(t, "GET", "http://api.github.com/repos/foo", "agent-1"))
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if !res.Decision.Allowed {
		t.Fatal("izinli cagri reddedildi")
	}
	if res.ReceiptID != "rcp-stored" {
		t.Errorf("ReceiptID = %q", res.ReceiptID)
	}
	if len(st.saved) != 1 {
		t.Fatalf("kalici yazilan receipt sayisi = %d", len(st.saved))
	}
	if err := receipt.Verify(sg.PublicKey(), st.saved[0]); err != nil {
		t.Fatalf("kaydedilen receipt dogrulanamadi: %v", err)
	}
	if !st.saved[0].Allowed || st.saved[0].AgentID != "agent-1" || st.saved[0].Host != "api.github.com" {
		t.Errorf("receipt icerigi beklenmedik: %+v", st.saved[0])
	}
}

// Reddedilen cagri da kanit uretmeli — denetimde asil onemli olan bu.
func TestHandle_DeniedAlsoProducesReceipt(t *testing.T) {
	sg := testSigner(t)
	st := &fakeStore{}
	m := New(fakeEval{allow: false}, sg, st, nil)

	res, err := m.Handle(context.Background(), newReq(t, "POST", "http://evil.example.com/x", "agent-9"))
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if res.Decision.Allowed {
		t.Fatal("izinsiz cagriya izin verildi")
	}
	if len(st.saved) != 1 || st.saved[0].Allowed {
		t.Fatalf("reddedilen cagri icin receipt yanlis: %+v", st.saved)
	}
	if err := receipt.Verify(sg.PublicKey(), st.saved[0]); err != nil {
		t.Fatalf("red receipt'i dogrulanamadi: %v", err)
	}
}

// Receipt kaydedilemiyorsa cagri GECMEMELI (fail-closed).
func TestHandle_StoreFailureFailsClosed(t *testing.T) {
	m := New(fakeEval{allow: true}, testSigner(t), &fakeStore{err: errors.New("db down")}, nil)

	res, err := m.Handle(context.Background(), newReq(t, "GET", "http://api.github.com/repos", "agent-1"))
	if err == nil {
		t.Fatal("hata bekleniyordu")
	}
	if res.Decision.Allowed {
		t.Fatal("kanit yazilamadigi halde cagriya IZIN VERILDI — fail-closed ihlali")
	}
}

// Imzalama basarisizsa da cagri gecmemeli.
func TestHandle_SignerFailureFailsClosed(t *testing.T) {
	st := &fakeStore{}
	m := New(fakeEval{allow: true}, failingSigner{}, st, nil)

	res, err := m.Handle(context.Background(), newReq(t, "GET", "http://api.github.com/repos", "agent-1"))
	if err == nil {
		t.Fatal("hata bekleniyordu")
	}
	if res.Decision.Allowed {
		t.Fatal("imzalanamadigi halde cagriya IZIN VERILDI — fail-closed ihlali")
	}
	if len(st.saved) != 0 {
		t.Error("imza basarisizken receipt kaydedilmemeliydi")
	}
}

// Kimliksiz istek degerlendirilemez, izin de verilmez.
func TestHandle_MissingAgentIDDenied(t *testing.T) {
	st := &fakeStore{}
	m := New(fakeEval{allow: true}, testSigner(t), st, nil)

	res, err := m.Handle(context.Background(), newReq(t, "GET", "http://api.github.com/repos", ""))
	if !errors.Is(err, transport.ErrMissingAgentID) {
		t.Fatalf("hata = %v, ErrMissingAgentID bekleniyordu", err)
	}
	if res.Decision.Allowed {
		t.Fatal("kimliksiz istege izin verildi")
	}
	if len(st.saved) != 0 {
		t.Error("degerlendirilemeyen istek icin receipt yazilmamaliydi")
	}
}

// Receipt, KANONIK yolu tasimali (ham "/repos/../admin" degil) — yoksa
// kanit, fiilen degerlendirilen seyden baskasini iddia eder.
func TestHandle_ReceiptCarriesCanonicalPath(t *testing.T) {
	st := &fakeStore{}
	m := New(fakeEval{allow: true}, testSigner(t), st, nil)

	if _, err := m.Handle(context.Background(),
		newReq(t, "GET", "http://api.github.com/repos/../admin", "agent-1")); err != nil {
		t.Fatal(err)
	}
	if st.saved[0].Path != "/admin" {
		t.Errorf("receipt.Path = %q, kanonik /admin olmaliydi", st.saved[0].Path)
	}
}
