// Package receipt, GKO-3: imzalı action receipt üretir ve doğrular.
//
// GÖKKALKAN her dış çağrıyı mediator olarak imzalar; ortaya çıkan receipt
// "bu agent, şu anda, şu çağrıyı yapmak istedi ve şu kararı aldık"
// iddiasının sonradan doğrulanabilir kanıtıdır (PROJECT_PLAN.md EPIC GK-D,
// compliance köprüsü). GÖKTÜRK'teki cosign/SBOM imzalama disiplininin
// (OPS-4) uygulama katmanındaki karşılığı.
//
// Ed25519 kullanılır: stdlib'de var (yeni bağımlılık yok), imzalar kısa ve
// deterministiktir.
package receipt

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Receipt, tek bir dış çağrı denemesinin imzalanacak içeriğidir.
type Receipt struct {
	ID       string    `json:"id"`
	AgentID  string    `json:"agent_id"`
	Method   string    `json:"method"`
	Host     string    `json:"host"`
	Path     string    `json:"path"`
	Allowed  bool      `json:"allowed"`
	Reason   string    `json:"reason"`
	IssuedAt time.Time `json:"issued_at"`
}

// SignedReceipt, Receipt + imza zarfıdır.
type SignedReceipt struct {
	Receipt
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"` // base64 (std, padding'li)
}

var (
	// ErrInvalidSignature, imza doğrulanamadığında döner.
	ErrInvalidSignature = errors.New("receipt: imza gecersiz")
	// ErrKeyMissing, imzalama anahtarı sağlanmadığında döner.
	ErrKeyMissing = errors.New("receipt: imzalama anahtari yok")
)

// canonicalBytes, imzalanacak KANONİK baytları üretir.
//
// JSON kullanılmaz: alan sırası/boşluk/escape farkları aynı receipt için
// farklı bayt dizileri üretebilir ve doğrulama imzayı reddeder.
//
// Her alan uzunluk-önekli yazılır. Bu sadece bir biçim tercihi değil,
// güvenlik gereğidir: alanlar düz birleştirilseydi
// (Host="a", Path="bc") ile (Host="ab", Path="c") AYNI baytları üretir ve
// tek bir imza iki farklı çağrıyı doğrularadı — saldırgan izinli bir
// çağrının imzasını izinsiz bir çağrıya taşıyabilirdi.
func (r Receipt) canonicalBytes() []byte {
	var out []byte
	writeField := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		out = append(out, n[:]...)
		out = append(out, s...)
	}

	out = append(out, "gokkalkan-receipt-v1\x00"...)
	writeField(r.ID)
	writeField(r.AgentID)
	writeField(r.Method)
	writeField(r.Host)
	writeField(r.Path)
	if r.Allowed {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	writeField(r.Reason)

	// Zaman MIKROSANIYE cozunurlugunde imzalanir, nanosaniye degil.
	//
	// Gerekce (gercek DB'ye karsi olculdu): Postgres timestamptz mikrosaniye
	// tutar ve YUVARLAR — '...123456789' yazinca '...123457' okunur. Imza
	// nanosaniye uzerinden hesaplansaydi DB'den geri okunan HER receipt
	// dogrulanamazdi, yani kanit degeri sifir olurdu. Depolama ortaminin
	// cozunurlugunde imzalayarak tur-gidis-donus kayipsiz olur.
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(normalizeTime(r.IssuedAt).UnixMicro()))
	out = append(out, ts[:]...)

	return out
}

// normalizeTime, zamani UTC'ye ve mikrosaniyeye indirger. Postgres da
// yuvarladigi icin Round kullanilir (Truncate degil): boylece imzalanan
// deger ile saklanan deger birebir ayni olur.
func normalizeTime(t time.Time) time.Time {
	return t.UTC().Round(time.Microsecond)
}

// Signer, receipt'leri imzalar.
type Signer struct {
	priv  ed25519.PrivateKey
	keyID string
}

// NewSignerFromSeed, hex kodlanmış 32 baytlık bir tohumdan Signer üretir.
//
// Anahtar ASLA repoda/imajda düz metin durmaz: operatör onu ortam
// değişkeni veya secret olarak enjekte eder (GÖKTÜRK'teki HMAC_KEY ve
// OPS-11'deki SSH key disiplininin aynısı).
func NewSignerFromSeed(seedHex string) (*Signer, error) {
	if seedHex == "" {
		return nil, ErrKeyMissing
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, fmt.Errorf("receipt: tohum hex cozulemedi: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("receipt: tohum %d bayt olmali, %d geldi", ed25519.SeedSize, len(seed))
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("receipt: public key tipi beklenmedik")
	}
	// KeyID, dogrulayanin hangi anahtarla imzalandigini bilmesi icin
	// public key'in kisa hex ozetidir; gizli bilgi tasimaz.
	return &Signer{priv: priv, keyID: hex.EncodeToString(pub[:8])}, nil
}

// KeyID, imzalarda taşınan anahtar tanımlayıcısını döner.
func (s *Signer) KeyID() string { return s.keyID }

// PublicKey, doğrulama için açık anahtarı döner.
func (s *Signer) PublicKey() ed25519.PublicKey {
	pub, _ := s.priv.Public().(ed25519.PublicKey)
	return pub
}

// Sign, receipt'i imzalar.
//
// Donen SignedReceipt'in IssuedAt'i NORMALIZE edilmistir (UTC, mikrosaniye).
// Cagiran KALICI OLARAK BUNU yazmalidir: imzalanan deger ile saklanan deger
// ayni olmazsa, geri okunan kanit dogrulanamaz.
func (s *Signer) Sign(r Receipt) (SignedReceipt, error) {
	if s == nil || len(s.priv) == 0 {
		return SignedReceipt{}, ErrKeyMissing
	}
	r.IssuedAt = normalizeTime(r.IssuedAt)
	sig := ed25519.Sign(s.priv, r.canonicalBytes())
	return SignedReceipt{
		Receipt:   r,
		KeyID:     s.keyID,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Verify, imzalı bir receipt'i açık anahtarla doğrular.
// İçerik bir bit bile değişmişse ErrInvalidSignature döner.
func Verify(pub ed25519.PublicKey, sr SignedReceipt) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("receipt: public key %d bayt olmali", ed25519.PublicKeySize)
	}
	sig, err := base64.StdEncoding.DecodeString(sr.Signature)
	if err != nil {
		return fmt.Errorf("receipt: imza base64 cozulemedi: %w", err)
	}
	if !ed25519.Verify(pub, sr.canonicalBytes(), sig) {
		return ErrInvalidSignature
	}
	return nil
}
