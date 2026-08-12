package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/GokturkFK/gokkalkan/internal/receipt"
	"github.com/GokturkFK/gokturk-core/correlate"
)

type fakeStore struct {
	alerts     []correlate.Alert
	receipts   []receipt.SignedReceipt
	alertsErr  error
	receiptErr error
	gotLimit   int
	gotAgentID string
}

func (f *fakeStore) Alerts(_ context.Context, limit int) ([]correlate.Alert, error) {
	f.gotLimit = limit
	return f.alerts, f.alertsErr
}

func (f *fakeStore) ReceiptsByAgent(_ context.Context, agentID string, limit int) ([]receipt.SignedReceipt, error) {
	f.gotAgentID, f.gotLimit = agentID, limit
	return f.receipts, f.receiptErr
}

func newServer(fs *fakeStore) http.Handler {
	mux := http.NewServeMux()
	New(fs, slog.New(slog.NewTextHandler(io.Discard, nil))).Routes(mux)
	return mux
}

func do(t *testing.T, h http.Handler, method, url string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, url, nil))
	return rec
}

// Panelin gordugu SEKIL, GOKTURK'unkiyle ayni olmali — bu ucun tum amaci bu.
func TestAlerts_ShapeMatchesGokturkContract(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	fs := &fakeStore{alerts: []correlate.Alert{{
		ID: "a1", Severity: correlate.SeverityCritical, Technique: "AML.T0053",
		Source: "agent-1", Status: correlate.StatusOpen,
		FirstSeen: now.Add(-time.Minute), LastSeen: now, TripCount: 2,
	}}}

	rec := do(t, newServer(fs), http.MethodGet, "/api/v1/alerts")
	if rec.Code != http.StatusOK {
		t.Fatalf("kod = %d", rec.Code)
	}

	var got []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("JSON cozulemedi: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("alarm sayisi = %d", len(got))
	}
	// Streamlit paneli (dashboard/app.py) bu alan adlarini birebir okuyor.
	for _, key := range []string{"severity", "technique", "source", "status", "first_seen", "last_seen", "trip_count"} {
		if _, ok := got[0][key]; !ok {
			t.Errorf("wire alani eksik: %q (gelen: %v)", key, got[0])
		}
	}
	if got[0]["severity"] != "Critical" || got[0]["trip_count"].(float64) != 2 {
		t.Errorf("degerler beklenmedik: %v", got[0])
	}
}

// Bos listede null DEGIL [] donmeli (panel dizi bekliyor).
func TestAlerts_EmptyReturnsArrayNotNull(t *testing.T) {
	rec := do(t, newServer(&fakeStore{}), http.MethodGet, "/api/v1/alerts")
	if rec.Code != http.StatusOK {
		t.Fatalf("kod = %d", rec.Code)
	}
	if body := rec.Body.String(); body != "[]\n" {
		t.Errorf("govde = %q, istenen \"[]\"", body)
	}
}

func TestAlerts_StoreErrorIs500(t *testing.T) {
	fs := &fakeStore{alertsErr: errors.New("db down")}
	rec := do(t, newServer(fs), http.MethodGet, "/api/v1/alerts")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("kod = %d, 500 bekleniyordu", rec.Code)
	}
}

func TestLimit(t *testing.T) {
	cases := []struct {
		url  string
		want int
		code int
	}{
		{"/api/v1/alerts", DefaultLimit, http.StatusOK},
		{"/api/v1/alerts?limit=5", 5, http.StatusOK},
		{"/api/v1/alerts?limit=99999", MaxLimit, http.StatusOK}, // ust sinira kirpilir
		{"/api/v1/alerts?limit=0", 0, http.StatusBadRequest},
		{"/api/v1/alerts?limit=-3", 0, http.StatusBadRequest},
		{"/api/v1/alerts?limit=abc", 0, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			fs := &fakeStore{}
			rec := do(t, newServer(fs), http.MethodGet, tc.url)
			if rec.Code != tc.code {
				t.Fatalf("kod = %d, istenen %d", rec.Code, tc.code)
			}
			if tc.code == http.StatusOK && fs.gotLimit != tc.want {
				t.Errorf("store'a giden limit = %d, istenen %d", fs.gotLimit, tc.want)
			}
		})
	}
}

func TestAlerts_MethodNotAllowed(t *testing.T) {
	rec := do(t, newServer(&fakeStore{}), http.MethodPost, "/api/v1/alerts")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("kod = %d, 405 bekleniyordu", rec.Code)
	}
}

// agent_id olmadan tum kanitlar dokulmemeli.
func TestReceipts_RequiresAgentID(t *testing.T) {
	rec := do(t, newServer(&fakeStore{}), http.MethodGet, "/api/v1/receipts")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("kod = %d, 400 bekleniyordu", rec.Code)
	}
}

func TestReceipts_ReturnsSignedEnvelope(t *testing.T) {
	fs := &fakeStore{receipts: []receipt.SignedReceipt{{
		Receipt: receipt.Receipt{
			ID: "r1", AgentID: "agent-1", Method: "GET", Host: "api.github.com",
			Path: "/repos", Allowed: false, Reason: "deny-by-default",
			IssuedAt: time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC),
		},
		KeyID: "abc123", Signature: "c2ln",
	}}}

	rec := do(t, newServer(fs), http.MethodGet, "/api/v1/receipts?agent_id=agent-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("kod = %d", rec.Code)
	}
	if fs.gotAgentID != "agent-1" {
		t.Errorf("store'a giden agent_id = %q", fs.gotAgentID)
	}

	var got []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	// Imza zarfi disari cikmali, yoksa kanit disaridan dogrulanamaz.
	for _, key := range []string{"id", "agent_id", "method", "host", "path", "allowed", "issued_at", "key_id", "signature"} {
		if _, ok := got[0][key]; !ok {
			t.Errorf("alan eksik: %q (gelen: %v)", key, got[0])
		}
	}
}

func TestReceipts_EmptyReturnsArrayNotNull(t *testing.T) {
	rec := do(t, newServer(&fakeStore{}), http.MethodGet, "/api/v1/receipts?agent_id=x")
	if body := rec.Body.String(); body != "[]\n" {
		t.Errorf("govde = %q", body)
	}
}

func TestReceipts_StoreErrorIs500(t *testing.T) {
	fs := &fakeStore{receiptErr: errors.New("db down")}
	rec := do(t, newServer(fs), http.MethodGet, "/api/v1/receipts?agent_id=x")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("kod = %d", rec.Code)
	}
}
