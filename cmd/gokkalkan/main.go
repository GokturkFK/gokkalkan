// GÖKKALKAN binary'si.
//
// İki ayrı HTTP sunucusu çalıştırır:
//   - HTTPAddr (:8090): /healthz + okuma API'si (GET /api/v1/alerts, /receipts)
//   - ProxyAddr (:8091): agent egress proxy — internal/gateway.Handler, tüm
//     path/host'ları yakalar; okuma API'siyle aynı mux'ta olamaz (çakışma).
//
// internal/proxy (karar), internal/mediator (kanıt), internal/enforce
// (korelasyon→kesme), internal/receipt (imza) burada tek bir akışta
// birleşir — PROJECT_PLAN.md DoD madde 1-3'ün fiilen çalışması bu
// bağlantıya bağlıydı.
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/GokturkFK/gokkalkan/internal/api"
	"github.com/GokturkFK/gokkalkan/internal/config"
	"github.com/GokturkFK/gokkalkan/internal/enforce"
	"github.com/GokturkFK/gokkalkan/internal/gateway"
	"github.com/GokturkFK/gokkalkan/internal/mediator"
	"github.com/GokturkFK/gokkalkan/internal/proxy"
	"github.com/GokturkFK/gokkalkan/internal/receipt"
	"github.com/GokturkFK/gokkalkan/internal/store"
	"github.com/GokturkFK/gokturk-core/trap"
	_ "github.com/lib/pq"
)

func main() {
	// Ayni binary "healthcheck" arguman ile calistirilir (distroless imajda
	// wget/curl yok — bkz. gokkalkan.Dockerfile). control-api ile ayni desen.
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck(envOrDefault("HTTP_ADDR", ":8090")))
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("config yuklenemedi", "err", err)
		os.Exit(1)
	}

	db, err := sql.Open("postgres", cfg.DBDSN)
	if err != nil {
		logger.Error("postgres surucusu acilamadi", "err", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()

	pingCtx, cancelPing := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelPing()
	if err := db.PingContext(pingCtx); err != nil {
		logger.Error("postgres'e baglanilamadi", "err", err)
		os.Exit(1)
	}

	signer, err := receipt.NewSignerFromSeed(cfg.ReceiptSeedHex)
	if err != nil {
		logger.Error("receipt imzalayici kurulamadi", "err", err)
		os.Exit(1)
	}

	st := store.New(db)
	enforcer := proxy.NewEnforcer(st)
	enforceEngine := enforce.New(st, logger)
	med := mediator.New(enforcer, signer, st, nil)

	gw, err := gateway.New(med, enforceEngine, newUUIDv4, nil, nil, logger)
	if err != nil {
		logger.Error("gateway kurulamadi", "err", err)
		os.Exit(1)
	}

	readMux := http.NewServeMux()
	readMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	api.New(st, logger).Routes(readMux)

	readSrv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           readMux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	proxySrv := &http.Server{
		Addr:              cfg.ProxyAddr,
		Handler:           gw,
		ReadHeaderTimeout: 5 * time.Second,
	}

	logger.Info("gokkalkan basladi",
		"http_addr", cfg.HTTPAddr,
		"proxy_addr", cfg.ProxyAddr,
		"nats_url", cfg.NATSURL,
		"trip_subject", trap.SubjectTripEvents,
		"receipt_key_id", signer.KeyID(),
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go serve(readSrv, "okuma API", logger)
	go serve(proxySrv, "egress proxy", logger)

	<-ctx.Done()
	logger.Info("kapatiliyor")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := readSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("okuma API graceful shutdown basarisiz", "err", err)
	}
	if err := proxySrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("egress proxy graceful shutdown basarisiz", "err", err)
	}
}

func serve(srv *http.Server, name string, logger *slog.Logger) {
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error(name+" sunucu hatasi", "err", err)
		os.Exit(1)
	}
}

// newUUIDv4, crypto/rand ile RFC 4122 v4 uuid uretir. internal/mediator'daki
// unexported newUUIDv4 ile ayni desen; harici bagimlilik eklememek icin
// burada da elle kuruldu.
func newUUIDv4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand basarisizligi isletim sisteminin entropi kaynagi
		// bozuk demektir; bu asamada devam etmek anlamsiz.
		panic(fmt.Sprintf("main: uuid uretilemedi: %v", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40 // surum 4
	b[8] = (b[8] & 0x3f) | 0x80 // varyant RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func runHealthcheck(addr string) int {
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://localhost"+addr+"/healthz", nil)
	if err != nil {
		return 1
	}
	resp, err := client.Do(req)
	if err != nil {
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
