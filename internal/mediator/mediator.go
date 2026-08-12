// Package mediator, GKO-3'ün asıl işini yapar: GÖKKALKAN her dış çağrıyı
// aracı (mediator) olarak değerlendirir ve o değerlendirmeyi imzalar.
//
// Akış: HTTP isteği → kanonik hale getir (transport) → izin kararı
// (proxy.Enforcer) → kararı imzala (receipt.Signer) → kanıtı kalıcı yaz.
//
// Karar ve kanıt AYNI anda üretilir: panelde bir alarm, elde de o alarma
// yol açan çağrının imzalı kaydı bulunur (PROJECT_PLAN.md EPIC GK-D).
package mediator

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/GokturkFK/gokkalkan/internal/proxy"
	"github.com/GokturkFK/gokkalkan/internal/receipt"
	"github.com/GokturkFK/gokkalkan/internal/transport"
)

// ReceiptStore, imzalı receipt'i kalıcı yazar. Gerçek implementasyon:
// internal/store.
type ReceiptStore interface {
	InsertReceipt(ctx context.Context, sr receipt.SignedReceipt) (string, error)
}

// Evaluator, izin kararını üretir (proxy.Enforcer bunu karşılar).
type Evaluator interface {
	Evaluate(ctx context.Context, req proxy.Request) proxy.Decision
}

// Signer, receipt'i imzalar (receipt.Signer bunu karşılar).
type Signer interface {
	Sign(r receipt.Receipt) (receipt.SignedReceipt, error)
}

// Mediator, karar + kanıt üretimini birleştirir.
type Mediator struct {
	eval   Evaluator
	signer Signer
	store  ReceiptStore
	now    func() time.Time
	idFn   func() (string, error)
}

// New, bir Mediator kurar. now/idFn nil bırakılırsa varsayılanlar kullanılır.
func New(eval Evaluator, signer Signer, store ReceiptStore, now func() time.Time) *Mediator {
	if now == nil {
		now = time.Now
	}
	return &Mediator{eval: eval, signer: signer, store: store, now: now, idFn: newUUIDv4}
}

// WithIDFunc, receipt kimliği üretimini değiştirir (testler için).
func (m *Mediator) WithIDFunc(fn func() (string, error)) *Mediator {
	m.idFn = fn
	return m
}

// newUUIDv4, crypto/rand ile RFC 4122 v4 uuid üretir. Harici bağımlılık
// eklememek için elle kuruldu (bu repo şu an sadece lib/pq'ya bağlı).
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("mediator: uuid uretilemedi: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // surum 4
	b[8] = (b[8] & 0x3f) | 0x80 // varyant RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// Result, tek bir çağrının değerlendirme sonucudur.
type Result struct {
	Decision proxy.Decision
	Receipt  receipt.SignedReceipt
	// ReceiptID, kalıcı yazılan kaydın kimliğidir.
	ReceiptID string
}

// Handle, bir HTTP isteğini değerlendirir ve imzalı kanıtını üretir.
//
// FAIL-CLOSED: kanıt üretilemiyorsa (imzalama veya kalıcı yazma başarısız)
// çağrıya İZİN VERİLMEZ, hata döner. Gerekçe: bu ürünün iddiası "her dış
// çağrının denetlenebilir kaydı vardır"; kaydı olmayan bir çağrıyı geçirmek
// o iddiayı sessizce boşa çıkarır. Aynı disiplin proxy'nin
// deny-by-default'unda da var — emin olunmayan durumda geçirme.
func (m *Mediator) Handle(ctx context.Context, r *http.Request) (Result, error) {
	req, err := transport.FromRequest(r)
	if err != nil {
		// Kanonik hale getirilemeyen veya kimliksiz istek degerlendirilemez.
		// Bu bir KARAR degil, girdi hatasidir; cagiran reddetmelidir.
		return Result{
			Decision: proxy.Decision{Allowed: false, Reason: fmt.Sprintf("istek degerlendirilemedi: %v", err)},
		}, err
	}

	decision := m.eval.Evaluate(ctx, req)

	// Kimlik IMZADAN ONCE uretilir. DB'nin uretmesine birakilsaydi imza
	// bos ID uzerinden hesaplanir, kalici kayitta ID dolu olurdu ve geri
	// okunan kanit HIC dogrulanmazdi (gercek DB'ye karsi yasandi).
	id, err := m.idFn()
	if err != nil {
		return Result{Decision: denied("kanit kimligi uretilemedi")}, err
	}

	signed, err := m.signer.Sign(receipt.Receipt{
		ID:       id,
		AgentID:  req.AgentID,
		Method:   req.Method,
		Host:     req.Host,
		Path:     req.Path,
		Allowed:  decision.Allowed,
		Reason:   decision.Reason,
		IssuedAt: m.now(),
	})
	if err != nil {
		return Result{Decision: denied("kanit imzalanamadi")}, fmt.Errorf("mediator: receipt imzalanamadi: %w", err)
	}

	// Sign, IssuedAt'i normalize etti; DB'ye YAZILAN da o normalize deger
	// olmali (signed'i oldugu gibi veriyoruz).
	storedID, err := m.store.InsertReceipt(ctx, signed)
	if err != nil {
		return Result{Decision: denied("kanit kaydedilemedi")}, fmt.Errorf("mediator: receipt yazilamadi: %w", err)
	}

	return Result{Decision: decision, Receipt: signed, ReceiptID: storedID}, nil
}

func denied(reason string) proxy.Decision {
	return proxy.Decision{Allowed: false, Reason: reason}
}

// ErrNoSigner, Mediator imzalayıcısız kurulduğunda Handle'dan döner.
var ErrNoSigner = errors.New("mediator: imzalayici yok")
