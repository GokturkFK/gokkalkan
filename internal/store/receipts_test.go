package store

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/GokturkFK/gokkalkan/internal/mediator"
	"github.com/GokturkFK/gokkalkan/internal/proxy"
	"github.com/GokturkFK/gokkalkan/internal/receipt"
	"github.com/GokturkFK/gokkalkan/internal/transport"
)

const receiptSeed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

func TestInsertAndReadReceipt(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()

	sg, err := receipt.NewSignerFromSeed(receiptSeed)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Now().UTC().Truncate(time.Microsecond)
	signed, err := sg.Sign(receipt.Receipt{
		ID:      "11111111-2222-3333-4444-555555555555",
		AgentID: "agent-1", Method: "GET", Host: "api.github.com",
		Path: "/repos/foo", Allowed: true, Reason: "allowlist eslesmesi", IssuedAt: issued,
	})
	if err != nil {
		t.Fatal(err)
	}

	id, err := s.InsertReceipt(ctx, signed)
	if err != nil {
		t.Fatalf("InsertReceipt: %v", err)
	}
	if id == "" {
		t.Fatal("bos id dondu")
	}

	got, err := s.ReceiptsByAgent(ctx, "agent-1", 10)
	if err != nil {
		t.Fatalf("ReceiptsByAgent: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("receipt sayisi = %d", len(got))
	}

	// KRITIK: DB'den geri okunan receipt HALA dogrulanabilir olmali.
	// Zaman duyarligi veya alan kaybi imzayi bozarsa kanit degeri sifirlanir.
	if err := receipt.Verify(sg.PublicKey(), got[0]); err != nil {
		t.Fatalf("DB'den okunan receipt dogrulanamadi: %v", err)
	}
	if got[0].AgentID != "agent-1" || got[0].Path != "/repos/foo" || !got[0].Allowed {
		t.Errorf("receipt icerigi beklenmedik: %+v", got[0])
	}
}

func TestReceiptsByAgent_FiltersAndOrders(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()
	sg, _ := receipt.NewSignerFromSeed(receiptSeed)
	base := time.Now().UTC().Truncate(time.Microsecond)

	n := 0
	mk := func(agent string, at time.Time) {
		n++
		sr, err := sg.Sign(receipt.Receipt{
			ID:      fmt.Sprintf("11111111-2222-3333-4444-%012d", n),
			AgentID: agent, Method: "GET", Host: "h", Path: "/p", Allowed: false, IssuedAt: at,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.InsertReceipt(ctx, sr); err != nil {
			t.Fatal(err)
		}
	}
	mk("agent-1", base.Add(-2*time.Minute))
	mk("agent-1", base)
	mk("agent-2", base)

	got, err := s.ReceiptsByAgent(ctx, "agent-1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("agent-1 receipt sayisi = %d, istenen 2", len(got))
	}
	if got[0].IssuedAt.Before(got[1].IssuedAt) {
		t.Error("en yeni once siralanmadi")
	}
}

// Uctan uca (GKO-3): gercek Enforcer + gercek Signer + gercek DB.
// Bir agent izinli ve izinsiz birer cagri dener; ikisi de imzali kanit
// birakir ve kanitlar DB'den okununca hala dogrulanabilir.
func TestE2E_MediatorProducesVerifiableEvidence(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()

	agentID := newAgent(t, s, "agent-mediator")
	if _, err := s.db.Exec(
		`INSERT INTO agent_allowlist (agent_id, method, host, path_prefix) VALUES ($1,'*','api.github.com','/repos')`,
		agentID); err != nil {
		t.Fatal(err)
	}

	sg, err := receipt.NewSignerFromSeed(receiptSeed)
	if err != nil {
		t.Fatal(err)
	}
	m := mediator.New(proxy.NewEnforcer(s), sg, s, nil)

	// 1) Izinli cagri
	allowed := httptest.NewRequest("GET", "http://api.github.com/repos/foo", nil)
	allowed.Header.Set(transport.HeaderAgentID, agentID)
	res, err := m.Handle(ctx, allowed)
	if err != nil {
		t.Fatalf("izinli cagri: %v", err)
	}
	if !res.Decision.Allowed {
		t.Fatalf("izinli cagri reddedildi: %s", res.Decision.Reason)
	}

	// 2) Izinsiz cagri (allowlist disi host)
	denied := httptest.NewRequest("POST", "http://evil.example.com/steal", nil)
	denied.Header.Set(transport.HeaderAgentID, agentID)
	res2, err := m.Handle(ctx, denied)
	if err != nil {
		t.Fatalf("izinsiz cagri: %v", err)
	}
	if res2.Decision.Allowed {
		t.Fatal("allowlist disi cagriya izin verildi")
	}

	// Iki kanit da DB'de ve HALA dogrulanabilir.
	stored, err := s.ReceiptsByAgent(ctx, agentID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 2 {
		t.Fatalf("kanit sayisi = %d, istenen 2", len(stored))
	}
	var sawAllowed, sawDenied bool
	for _, sr := range stored {
		if err := receipt.Verify(sg.PublicKey(), sr); err != nil {
			t.Errorf("kanit dogrulanamadi (%s %s%s): %v", sr.Method, sr.Host, sr.Path, err)
		}
		if sr.Allowed {
			sawAllowed = true
		} else {
			sawDenied = true
		}
	}
	if !sawAllowed || !sawDenied {
		t.Error("hem izinli hem izinsiz cagri icin kanit bekleniyordu")
	}
}

// Kesilmis agent: cagri reddedilir AMA kanit yine uretilir.
func TestE2E_RevokedAgentStillLeavesEvidence(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()

	agentID := newAgent(t, s, "agent-revoked-evidence")
	if _, err := s.db.Exec(
		`INSERT INTO agent_allowlist (agent_id, method, host, path_prefix) VALUES ($1,'*','api.github.com','/repos')`,
		agentID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAgent(ctx, agentID, time.Now()); err != nil {
		t.Fatal(err)
	}

	sg, _ := receipt.NewSignerFromSeed(receiptSeed)
	m := mediator.New(proxy.NewEnforcer(s), sg, s, nil)

	r := httptest.NewRequest("GET", "http://api.github.com/repos/foo", nil)
	r.Header.Set(transport.HeaderAgentID, agentID)
	res, err := m.Handle(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision.Allowed {
		t.Fatal("kesilmis agent'a izin verildi")
	}

	stored, err := s.ReceiptsByAgent(ctx, agentID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].Allowed {
		t.Fatalf("kesilmis agent'in denemesi kanit birakmadi: %+v", stored)
	}
	if err := receipt.Verify(sg.PublicKey(), stored[0]); err != nil {
		t.Fatalf("kanit dogrulanamadi: %v", err)
	}
}
