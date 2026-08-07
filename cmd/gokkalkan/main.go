// GKO-1: proje iskeleti. Sadece boot + config + healthz + graceful shutdown.
//
// Egress proxy'nin interception/allowlist/enforcement mantığı (GK-A, GK-B)
// bilinçli olarak burada DEĞİL — bu iskelet, o mantığın üzerine oturacağı
// çalışan bir binary sağlar (PROJECT_PLAN.md EPIC GK-C, GKO-1/GKO-2).
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/GokturkFK/gokkalkan/internal/config"
	"github.com/GokturkFK/gokturk-core/trap"
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

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	logger.Info("gokkalkan basladi",
		"http_addr", cfg.HTTPAddr,
		"nats_url", cfg.NATSURL,
		"trip_subject", trap.SubjectTripEvents,
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http sunucu hatasi", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("kapatiliyor")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown basarisiz", "err", err)
	}
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
