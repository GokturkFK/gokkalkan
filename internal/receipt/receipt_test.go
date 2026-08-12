package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

const testSeed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSignerFromSeed(testSeed)
	if err != nil {
		t.Fatalf("Signer olusturulamadi: %v", err)
	}
	return s
}

func sampleReceipt() Receipt {
	return Receipt{
		ID:       "rcp-1",
		AgentID:  "agent-1",
		Method:   "GET",
		Host:     "api.github.com",
		Path:     "/repos/foo",
		Allowed:  true,
		Reason:   "allowlist eslesmesi",
		IssuedAt: time.Date(2026, 8, 12, 12, 0, 0, 123456789, time.UTC),
	}
}

func TestSignAndVerify(t *testing.T) {
	s := newTestSigner(t)

	sr, err := s.Sign(sampleReceipt())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sr.Signature == "" || sr.KeyID == "" {
		t.Fatal("imza veya key_id bos")
	}
	if err := Verify(s.PublicKey(), sr); err != nil {
		t.Fatalf("kendi imzasi dogrulanamadi: %v", err)
	}
}

// Icerik degisirse imza TUTMAMALI — receipt'in tum degeri bu.
func TestVerify_TamperedContentRejected(t *testing.T) {
	s := newTestSigner(t)
	sr, err := s.Sign(sampleReceipt())
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(*SignedReceipt){
		"allowed false->true": func(x *SignedReceipt) { x.Allowed = !x.Allowed },
		"host degistirildi":   func(x *SignedReceipt) { x.Host = "evil.example.com" },
		"path degistirildi":   func(x *SignedReceipt) { x.Path = "/admin" },
		"agent degistirildi":  func(x *SignedReceipt) { x.AgentID = "agent-2" },
		"method degistirildi": func(x *SignedReceipt) { x.Method = "DELETE" },
		"zaman degistirildi":  func(x *SignedReceipt) { x.IssuedAt = x.IssuedAt.Add(time.Second) },
		"reason degistirildi": func(x *SignedReceipt) { x.Reason = "baska sebep" },
		"id degistirildi":     func(x *SignedReceipt) { x.ID = "rcp-2" },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			bad := sr
			tamper(&bad)
			if err := Verify(s.PublicKey(), bad); !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("degistirilmis receipt dogrulandi (hata=%v)", err)
			}
		})
	}
}

// Alan sinirlari belirsiz olmamali: (Host="ab", Path="c") ile
// (Host="a", Path="bc") AYNI imzayi uretmemeli. Uzunluk-onekli kanonik
// bicimin varlik sebebi bu.
func TestCanonicalBytes_FieldBoundariesUnambiguous(t *testing.T) {
	a := Receipt{Host: "ab", Path: "c", IssuedAt: time.Unix(0, 0).UTC()}
	b := Receipt{Host: "a", Path: "bc", IssuedAt: time.Unix(0, 0).UTC()}

	if string(a.canonicalBytes()) == string(b.canonicalBytes()) {
		t.Fatal("farkli receipt'ler ayni kanonik baytlari uretti — imza tasinabilir")
	}

	s := newTestSigner(t)
	sa, _ := s.Sign(a)
	sb := SignedReceipt{Receipt: b, KeyID: sa.KeyID, Signature: sa.Signature}
	if err := Verify(s.PublicKey(), sb); !errors.Is(err, ErrInvalidSignature) {
		t.Fatal("bir receipt'in imzasi baska bir receipt'i dogruladi")
	}
}

// Kanonik bicim deterministik olmali: ayni receipt her seferinde ayni imza.
func TestSign_Deterministic(t *testing.T) {
	s := newTestSigner(t)
	r := sampleReceipt()

	first, _ := s.Sign(r)
	for i := 0; i < 5; i++ {
		again, _ := s.Sign(r)
		if again.Signature != first.Signature {
			t.Fatalf("ayni receipt farkli imza uretti: %s != %s", again.Signature, first.Signature)
		}
	}
}

// Zaman dilimi farki imzayi bozmamali (UTC'ye normalize ediliyor).
func TestSign_TimezoneNormalized(t *testing.T) {
	s := newTestSigner(t)
	loc := time.FixedZone("UTC+3", 3*60*60)

	utc := sampleReceipt()
	other := sampleReceipt()
	other.IssuedAt = utc.IssuedAt.In(loc)

	a, _ := s.Sign(utc)
	b, _ := s.Sign(other)
	if a.Signature != b.Signature {
		t.Error("ayni an farkli zaman diliminde farkli imza uretti")
	}
}

func TestVerify_WrongKeyRejected(t *testing.T) {
	s := newTestSigner(t)
	sr, _ := s.Sign(sampleReceipt())

	otherSeed := strings.Repeat("ab", 32)
	other, err := NewSignerFromSeed(otherSeed)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(other.PublicKey(), sr); !errors.Is(err, ErrInvalidSignature) {
		t.Fatal("yanlis anahtarla dogrulandi")
	}
}

func TestNewSignerFromSeed_Validation(t *testing.T) {
	cases := map[string]string{
		"bos":       "",
		"hex degil": "zzzz",
		"kisa":      "0102",
		"uzun":      strings.Repeat("ab", 64),
	}
	for name, seed := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSignerFromSeed(seed); err == nil {
				t.Fatal("hata bekleniyordu")
			}
		})
	}
}

func TestKeyIDStableAcrossSigners(t *testing.T) {
	a := newTestSigner(t)
	b := newTestSigner(t)
	if a.KeyID() != b.KeyID() {
		t.Errorf("ayni tohum farkli KeyID uretti: %s != %s", a.KeyID(), b.KeyID())
	}

	other, _ := NewSignerFromSeed(strings.Repeat("cd", 32))
	if other.KeyID() == a.KeyID() {
		t.Error("farkli tohumlar ayni KeyID uretti")
	}
}

func TestVerify_BadPublicKeySize(t *testing.T) {
	s := newTestSigner(t)
	sr, _ := s.Sign(sampleReceipt())
	if err := Verify(ed25519.PublicKey{1, 2, 3}, sr); err == nil {
		t.Fatal("gecersiz public key boyutu icin hata bekleniyordu")
	}
}

func TestVerify_MalformedSignature(t *testing.T) {
	s := newTestSigner(t)
	sr, _ := s.Sign(sampleReceipt())
	sr.Signature = "!!!not-base64!!!"
	if err := Verify(s.PublicKey(), sr); err == nil {
		t.Fatal("bozuk base64 icin hata bekleniyordu")
	}
}

// Seed hex'i dogru cozulmus mu (public key beklenen tohumdan turemis mi).
func TestSignerDerivesFromSeed(t *testing.T) {
	s := newTestSigner(t)
	seed, _ := hex.DecodeString(testSeed)
	want, ok := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("public key tipi beklenmedik")
	}
	if !s.PublicKey().Equal(want) {
		t.Error("public key tohumdan dogru turetilmedi")
	}
}
