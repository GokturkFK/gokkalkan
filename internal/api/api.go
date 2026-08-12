// Package api, GKO-4: GÖKKALKAN'ın okuma API'sini sunar.
//
// Sözleşme, GÖKTÜRK'ün control-api'siyle BİREBİR aynıdır
// (GET /api/v1/alerts → correlate.Alert listesi). Sebebi doğrudan
// PROJECT_PLAN.md EPIC GK-E: agent olayları AYNI SOC feed'ine düşmeli.
// Aynı şekli döndürdüğümüz için mevcut Streamlit paneli hiçbir alan
// eşlemesi yapmadan bu ucu da okuyabilir.
//
// Ek olarak GÖKKALKAN'a özgü bir uç var: GET /api/v1/receipts — imzalı
// action receipt'ler (GKO-3). Alarmın yanında onu doğuran çağrının kanıtı.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/GokturkFK/gokkalkan/internal/receipt"
	"github.com/GokturkFK/gokturk-core/correlate"
)

// DefaultLimit, limit parametresi verilmediğinde döndürülen kayıt sayısı.
const DefaultLimit = 100

// MaxLimit, tek istekte döndürülebilecek en fazla kayıt sayısı.
// Sınırsız limit, panelin yanlışlıkla tüm tabloyu çekmesine yol açar.
const MaxLimit = 1000

// Store, API'nin ihtiyaç duyduğu okuma işlemlerini soyutlar.
// Handler'lar DB olmadan (fake ile) test edilebilsin diye arayüz.
type Store interface {
	Alerts(ctx context.Context, limit int) ([]correlate.Alert, error)
	ReceiptsByAgent(ctx context.Context, agentID string, limit int) ([]receipt.SignedReceipt, error)
}

// Server, HTTP uçlarını barındırır.
type Server struct {
	store  Store
	logger *slog.Logger
}

// New, bir Server kurar.
func New(store Store, logger *slog.Logger) *Server {
	return &Server{store: store, logger: logger}
}

// Routes, uçları bir mux'a bağlar.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/alerts", s.handleAlerts)
	mux.HandleFunc("/api/v1/receipts", s.handleReceipts)
}

// handleAlerts, GET /api/v1/alerts — alarmları en yeni önce listeler.
// GÖKTÜRK'ün aynı ucuyla şekil olarak özdeştir.
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "yalnizca GET")
		return
	}

	limit, err := parseLimit(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	alerts, err := s.store.Alerts(r.Context(), limit)
	if err != nil {
		s.logger.Error("alarmlar listelenemedi", "err", err)
		writeError(w, http.StatusInternalServerError, "alarmlar listelenemedi")
		return
	}
	// Panel bos listede de dizi bekler; null gondermek istemci tarafinda
	// ayri bir kontrol gerektirirdi (GOKTURK ile ayni davranis).
	if alerts == nil {
		alerts = []correlate.Alert{}
	}
	writeJSON(w, http.StatusOK, alerts)
}

// handleReceipts, GET /api/v1/receipts?agent_id=... — bir agent'ın imzalı
// action receipt'lerini listeler (denetim).
//
// agent_id ZORUNLUDUR: parametresiz çağrı tüm agent'ların tüm kanıtlarını
// dökerdi; bu uç denetim içindir, toplu dışa aktarım için değil.
func (s *Server) handleReceipts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "yalnizca GET")
		return
	}

	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "agent_id zorunlu")
		return
	}

	limit, err := parseLimit(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	receipts, err := s.store.ReceiptsByAgent(r.Context(), agentID, limit)
	if err != nil {
		s.logger.Error("receipt'ler listelenemedi", "err", err, "agent_id", agentID)
		writeError(w, http.StatusInternalServerError, "receiptler listelenemedi")
		return
	}
	if receipts == nil {
		receipts = []receipt.SignedReceipt{}
	}
	writeJSON(w, http.StatusOK, receipts)
}

func parseLimit(r *http.Request) (int, error) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return DefaultLimit, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0, errBadLimit
	}
	if n > MaxLimit {
		n = MaxLimit
	}
	return n, nil
}

type limitError string

func (e limitError) Error() string { return string(e) }

const errBadLimit = limitError("limit pozitif bir tamsayi olmali")

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Govde yazilmaya baslandigi icin durum kodu degistirilemez;
		// sessiz kalmamak icin loglanmasi cagirana birakilir.
		_ = err
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
