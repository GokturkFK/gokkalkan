// Package gateway, GÖKKALKAN'ın parçalarını (proxy karari, imzali receipt,
// korelasyon->enforcement) TEK bir istek akisinda birlestirir.
//
// internal/mediator, internal/enforce, internal/proxy, internal/receipt
// bagimsiz test edilebilir birimler olarak yazildi ama hicbiri bir HTTP
// dinleyicisine baglanmamisti (bkz. cmd/gokkalkan/main.go'nun eski yorumu:
// "onlari bir dinleyiciye baglamak sonraki is"). Bu paket o baglantidir:
//
//	Agent -> Handler.ServeHTTP -> mediator.Handle (karar+kanit)
//	  izinli     -> httputil.ReverseProxy ile gercek hedefe ilet
//	  reddedildi -> TripEvent uret -> enforce.Engine.Handle (korelasyon+kesme)
//
// Bu, PROJECT_PLAN.md DoD madde 1-3'un ("proxy keser", "Critical alarm +
// receipt uretilir", "mesru cagri engelsiz gecer") fiilen calisir hale
// gelmesi icin gereken tek eksik parcaydi.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/GokturkFK/gokkalkan/internal/enforce"
	"github.com/GokturkFK/gokkalkan/internal/mediator"
	"github.com/GokturkFK/gokkalkan/internal/proxy"
	"github.com/GokturkFK/gokturk-core/trap"
)

// ErrMissingIDFunc, New'e nil idFn verildiğinde döner. TripEvent.EventID
// üretimi zorunludur — sessiz bir varsayılana güvenmek yerine kurulum
// zamanında (çalışma zamanında değil) hata verilir.
var ErrMissingIDFunc = errors.New("gateway: idFn zorunlu")

// TechniqueUnauthorizedAccess, allowlist disi bir cagri denemesi icin
// correlate.Evaluate'e gecirilecek ATLAS teknik kodudur.
//
// docs/DECISIONS.md Karar 1 "Ucuncu kaynak" bolumunde gerekcelendirildi ve
// onaylandi: honeypot tetiklemesiyle (internal/honeypot) ayni teknik, farkli
// gozlem yuzeyi — ikisi de agent'in erisimi olmayan bir kaynagi kullanma
// girisimi, degisen SADECE nasil yakalandigi.
const TechniqueUnauthorizedAccess = "AML.T0053"

// EnforceEngine, karar reddedildiginde beslenecek korelasyon/enforcement
// motorudur (internal/enforce.Engine bunu karsilar; testlerde sahte ile
// degistirilebilir).
type EnforceEngine interface {
	Handle(ctx context.Context, ev trap.TripEvent, technique string) (enforce.Result, error)
}

// Handler, GÖKKALKAN egress proxy'sinin HTTP giris noktasidir.
type Handler struct {
	mediator *mediator.Mediator
	enforce  EnforceEngine
	target   *httputil.ReverseProxy
	idFn     func() string
	now      func() time.Time
	logger   *slog.Logger
}

// New, bir Handler kurar. idFn zorunludur (orn. production'da
// google/uuid.NewString); now nil birakilirsa time.Now kullanilir.
// transport nil birakilirsa http.DefaultTransport kullanilir — testler
// gercek DNS/network'e cikmadan sahte bir http.RoundTripper verebilir.
func New(m *mediator.Mediator, eng EnforceEngine, idFn func() string, now func() time.Time, rt http.RoundTripper, logger *slog.Logger) (*Handler, error) {
	if idFn == nil {
		return nil, ErrMissingIDFunc
	}
	if now == nil {
		now = time.Now
	}
	if rt == nil {
		rt = http.DefaultTransport
	}
	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			// Yalnizca semayi belirler. Hedef host/path, ServeHTTP'de
			// mediator'un DOGRULADIGI kanonik degerlerden yazilir
			// (bkz. forward) — istek burada yeniden yorumlanmaz.
			r.URL.Scheme = "https"
		},
		Transport: rt,
	}
	return &Handler{mediator: m, enforce: eng, target: rp, idFn: idFn, now: now, logger: logger}, nil
}

// ServeHTTP, GÖKKALKAN egress proxy'sinin ana giris noktasidir.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	res, err := h.mediator.Handle(r.Context(), r)
	if err != nil {
		// Kanit uretilemedi (imzalama/kayit basarisiz) -> fail-closed,
		// mediator.Handle zaten Decision.Allowed=false donmustur.
		h.logger.Error("mediator basarisiz", "err", err)
	}

	if !res.Decision.Allowed {
		h.recordDenial(r.Context(), r, res.Decision)
		h.writeDenied(w, res.Decision.Reason)
		return
	}

	h.forward(w, r, res.Receipt.Host, res.Receipt.Path)
}

// forward, izin verilen cagriyi gercek hedefe iletir.
//
// Hedef, istekten YENIDEN cikarilmaz; mediator'un kanonik hale getirip
// allowlist'e karsi dogruladigi (ve imzali receipt'e yazdigi) host/path
// kullanilir. Aksi halde karar bir degere, iletme baska bir degere
// bakabilirdi (parser-differential): allowlist'i "api.github.com" ile
// gecip baska bir hedefe cikmak mumkun olurdu.
//
// Bu ayni zamanda bir zorunluluk: agent'lar proxy'ye ORIGIN-FORM istek
// gonderir (`GET /path` + `Host:` basligi), o istekte r.URL.Host BOSTUR ve
// ReverseProxy "no Host in request URL" ile 502 doner. Testlerde
// httptest.NewRequest mutlak URL aldigi icin bu alan dolu gelir ve hata
// gorunmez — bkz. TestServeHTTP_AllowedCallForwardsOverRealListener.
func (h *Handler) forward(w http.ResponseWriter, r *http.Request, host, path string) {
	out := r.Clone(r.Context())
	out.URL.Host = host
	out.URL.Path = path
	// Hedefe giden Host basligi da dogrulanan deger olmali; aksi halde
	// istemcinin gonderdigi ham Host basligi upstream'e sizardi.
	out.Host = host
	h.target.ServeHTTP(w, out)
}

// recordDenial, reddedilen bir cagriyi TripEvent'e cevirip enforce
// motoruna besler. Motor hatasi istemciye YANSITILMAZ (red karari zaten
// verildi ve receipt zaten yazildi); yalnizca loglanir — korelasyon
// altyapisinin gecici bir arizasi, deny kararini geri almamalidir.
func (h *Handler) recordDenial(ctx context.Context, r *http.Request, dec proxy.Decision) {
	agentID := r.Header.Get("X-Gokkalkan-Agent-Id")

	raw, err := json.Marshal(struct {
		Method string `json:"method"`
		Host   string `json:"host"`
		Path   string `json:"path"`
		Reason string `json:"reason"`
	}{r.Method, r.Host, r.URL.Path, dec.Reason})
	if err != nil {
		h.logger.Error("trip event raw marshal hatasi", "err", err)
		return
	}

	ev := trap.TripEvent{
		EventID:    h.idFn(),
		Sensor:     "gateway",
		Source:     agentID,
		ObservedAt: h.now(),
		Raw:        raw,
	}

	if _, err := h.enforce.Handle(ctx, ev, TechniqueUnauthorizedAccess); err != nil {
		h.logger.Error("enforce basarisiz", "err", err, "agent_id", agentID)
	}
}

func (h *Handler) writeDenied(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": "reddedildi", "reason": reason}); err != nil {
		h.logger.Error("yanit yazilamadi", "err", err)
	}
}
