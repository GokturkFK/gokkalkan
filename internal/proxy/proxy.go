// Package proxy, GK-A1: agent egress proxy'nin karar mantığını uygular.
//
// Agent'ların yaptığı MCP/HTTP çağrılarını deny-by-default bir allowlist'e
// karşı değerlendirir. Karar mantığı bilerek taşıma katmanından (gerçek HTTP
// reverse proxy, GKO-2 wiring'in işi) ayrı tutuldu: bu paket sadece "bu
// çağrıya izin var mı" sorusuna saf bir fonksiyonla cevap verir, mock'larla
// test edilir (issue #2 AC'si).
//
// GÖKTÜRK'teki ErrNotATrip disiplininin aynısı burada da geçerli: emin
// olunmayan her durumda (agent bulunamadı, revoked, store hatası) erişim
// reddedilir — sıfır-FP değil, sıfır-yanlış-izin tezi.
package proxy

import (
	"context"
	"fmt"
	"path"
	"strings"
)

// Request, bir agent'ın yapmaya çalıştığı dış çağrıdır.
type Request struct {
	AgentID string
	Method  string
	Host    string
	Path    string
}

// Decision, bir Request için verilen erişim kararıdır.
type Decision struct {
	Allowed bool
	Reason  string
}

// AllowlistEntry, agent_allowlist tablosundaki (migrations/00002) bir
// satırın karşılığıdır.
type AllowlistEntry struct {
	Method     string // "*" = herhangi bir HTTP metodu
	Host       string
	PathPrefix string
}

// AgentStatus, agents tablosundaki (migrations/00002) bir agent'ın
// enforcement için gereken durumudur.
type AgentStatus struct {
	Revoked bool
}

// Store, proxy kararı için gereken agents/agent_allowlist verisine erişimi
// soyutlar. Gerçek Postgres implementasyonu wiring aşamasının (GKO-2) işi.
type Store interface {
	AgentStatus(ctx context.Context, agentID string) (*AgentStatus, error)
	Allowlist(ctx context.Context, agentID string) ([]AllowlistEntry, error)
}

// ErrAgentNotFound, Store.AgentStatus verilen agentID için bir kayıt
// bulamadığında döner.
var ErrAgentNotFound = errNotFound("proxy: agent bulunamadi")

type errNotFound string

func (e errNotFound) Error() string { return string(e) }

// Enforcer, deny-by-default karar mantığını yürütür.
type Enforcer struct {
	store Store
}

// NewEnforcer, verilen Store ile bir Enforcer kurar.
func NewEnforcer(store Store) *Enforcer {
	return &Enforcer{store: store}
}

// Evaluate, bir Request için Decision üretir. Emin olunmayan her durumda
// (agent yok, revoked, store hatası, allowlist boş/eşleşmeyen) erişim
// reddedilir — deny-by-default (issue #2 AC 1).
func (e *Enforcer) Evaluate(ctx context.Context, req Request) Decision {
	status, err := e.store.AgentStatus(ctx, req.AgentID)
	if err != nil {
		return Decision{Allowed: false, Reason: fmt.Sprintf("agent durumu alinamadi: %v", err)}
	}
	if status.Revoked {
		return Decision{Allowed: false, Reason: "agent kesilmis (revoked)"}
	}

	entries, err := e.store.Allowlist(ctx, req.AgentID)
	if err != nil {
		return Decision{Allowed: false, Reason: fmt.Sprintf("allowlist alinamadi: %v", err)}
	}

	for _, entry := range entries {
		if matches(entry, req) {
			return Decision{Allowed: true, Reason: "allowlist eslesmesi"}
		}
	}

	return Decision{Allowed: false, Reason: "allowlist'te esleseme yok (deny-by-default)"}
}

func matches(entry AllowlistEntry, req Request) bool {
	if entry.Method != "*" && !strings.EqualFold(entry.Method, req.Method) {
		return false
	}
	if !strings.EqualFold(entry.Host, req.Host) {
		return false
	}
	return pathWithinPrefix(req.Path, entry.PathPrefix)
}

// pathWithinPrefix, req'in normalize edilmiş yolunun (".."/"." temizlenmiş,
// "//" sadeleştirilmiş) prefix ile bir path SEGMENTİ sınırında eşleştiğini
// doğrular. Düz string prefix karşılaştırması "/repos" iznini "/repository"
// veya "/repos/../../secrets" gibi yollara da sızdırır (allowlist-bypass /
// path-traversal); segment sınırı ve path.Clean bunu kapatır.
func pathWithinPrefix(reqPath, prefix string) bool {
	cleanPath := path.Clean("/" + reqPath)
	cleanPrefix := path.Clean("/" + prefix)

	if cleanPrefix == "/" {
		return true
	}
	if cleanPath == cleanPrefix {
		return true
	}
	return strings.HasPrefix(cleanPath, cleanPrefix+"/")
}
