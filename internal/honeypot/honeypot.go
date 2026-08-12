// Package honeypot, GK-B1: sahte MCP tool provider'ını uygular.
//
// gokturk-core/trap.Provider'ın GÖKKALKAN'a özgü uygulaması. GÖKTÜRK'teki
// CredentialCanaryProvider ile aynı desen — gerçek bir kaynak gibi görünen
// ama dokunulunca TripEvent üreten bir tuzak; tip sabiti core'a taşınmadı
// (ürüne özgü), bu yüzden burada tanımlanır.
//
// DB erişimi bilerek Store arayüzü arkasına soyutlandı: gerçek Postgres
// implementasyonu wiring aşamasının (GKO-2/GKO-6) işi, bu paket sadece
// trap.Provider/trap.Decoder sözleşmesini karşılar.
package honeypot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/GokturkFK/gokturk-core/trap"
)

// TypeAgentHoneypot, bu ürüne özgü tuzak tipi (GÖKTÜRK'teki
// TypeCredentialCanary'nin muadili; core'a taşınmadı çünkü ürün-özel).
const TypeAgentHoneypot = "agent_honeypot"

// Tool, bir agent'ın gördüğü sahte MCP tool tanımıdır — provision anında
// üretilir ve honeypot_tools tablosuna yazılır (bkz. migrations/00002).
type Tool struct {
	ID          string
	Name        string
	Description string
	InputSchema json.RawMessage
	CreatedBy   string
	CreatedAt   time.Time
	RevokedAt   *time.Time
}

// Store, honeypot_tools tablosuna erişimi soyutlar. Gerçek Postgres
// implementasyonu bu paketin dışında (wiring), testler için sahte bir
// Store yeterlidir.
type Store interface {
	Create(ctx context.Context, t Tool) error
	FindByName(ctx context.Context, name string) (*Tool, error)
}

// ErrToolNotFound, Store.FindByName bir eşleşme bulamadığında döner.
var ErrToolNotFound = errors.New("honeypot: tool bulunamadi")

// NameGenerator, provision anında agent'a gösterilecek "inandırıcı" tool
// adı + açıklaması üretir. GK-B1'in tespit-edilemezlik işi burada değil —
// somut içerik (description'ın nasıl ikna edici olacağı) çağıranın alanı;
// bu paket sadece üretileni honeypot_tools'a yazıp TripEvent üretir.
type NameGenerator interface {
	Generate() (name, description string, inputSchema json.RawMessage)
}

// Provider, gokturk-core/trap.Provider'ı uygular: her çağrıda yeni bir
// sahte MCP tool provision eder.
type Provider struct {
	store Store
	names NameGenerator
	idFn  func() string
	now   func() time.Time
}

// NewProvider, verilen Store ve NameGenerator ile bir Provider kurar.
// idFn zorunludur (örn. production'da google/uuid.NewString) — nil
// bırakılırsa Provision hata döner, sessizce boş/çakışan ID üretmez.
// now nil bırakılırsa time.Now kullanılır.
func NewProvider(store Store, names NameGenerator, idFn func() string, now func() time.Time) *Provider {
	if now == nil {
		now = time.Now
	}
	return &Provider{store: store, names: names, idFn: idFn, now: now}
}

// Provision, gokturk-core/trap.Provider sözleşmesini karşılar: yeni bir
// honeypot tool üretir, Store'a yazar, Trap kaydını döner. Artifacts burada
// anlamsız (credential canary'nin aksine agent'a gizlice verilecek bir
// secret yok — tool'un kendisi zaten agent'ın tool listesinde görünür),
// bu yüzden boş döner; sözleşme bunu zorunlu kılmıyor.
func (p *Provider) Provision(ctx context.Context, createdBy string) (*trap.Trap, *trap.Artifacts, error) {
	if p.idFn == nil {
		return nil, nil, errors.New("honeypot: idFn tanimli degil")
	}

	name, description, schema := p.names.Generate()
	id := p.idFn()
	now := p.now()

	tool := Tool{
		ID:          id,
		Name:        name,
		Description: description,
		InputSchema: schema,
		CreatedBy:   createdBy,
		CreatedAt:   now,
	}

	if err := p.store.Create(ctx, tool); err != nil {
		return nil, nil, fmt.Errorf("honeypot: tool kaydedilemedi: %w", err)
	}

	metadata, err := json.Marshal(struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		InputSchema json.RawMessage `json:"input_schema"`
	}{name, description, schema})
	if err != nil {
		return nil, nil, fmt.Errorf("honeypot: metadata marshal hatasi: %w", err)
	}

	t := &trap.Trap{
		ID:        id,
		Type:      TypeAgentHoneypot,
		Username:  name,
		Metadata:  metadata,
		CreatedBy: createdBy,
		CreatedAt: now,
	}

	return t, &trap.Artifacts{}, nil
}

// Invocation, bir agent'ın honeypot tool'u çağırdığı ham gözlemdir.
// Sensör (proxy/MCP interceptor) bunu Decode'a geçirir.
type Invocation struct {
	ToolName   string
	AgentID    string
	Args       json.RawMessage
	ObservedAt time.Time
}

// Decoder, gokturk-core/trap.Decoder'ı uygular: bir tool çağrısının
// honeypot_tools'taki bir tuzağı tetikleyip tetiklemediğine bakar.
// Eşleşme yoksa ErrNotATrip döner — meşru tool çağrıları hiçbir event
// üretmez (sıfır-FP, issue #4 AC'sinin karşılığı).
type Decoder struct {
	store Store
	idFn  func() string
}

// NewDecoder, verilen Store ile bir Decoder kurar.
func NewDecoder(store Store, idFn func() string) *Decoder {
	return &Decoder{store: store, idFn: idFn}
}

// Decode, gokturk-core/trap.Decoder sözleşmesini karşılar.
func (d *Decoder) Decode(obs trap.RawObservation) (*trap.TripEvent, error) {
	if d.idFn == nil {
		return nil, errors.New("honeypot: idFn tanimli degil")
	}

	inv, err := parseInvocation(obs)
	if err != nil {
		return nil, fmt.Errorf("honeypot: gozlem cozumlenemedi: %w", err)
	}

	tool, err := d.store.FindByName(context.Background(), inv.ToolName)
	if err != nil {
		if errors.Is(err, ErrToolNotFound) {
			return nil, trap.ErrNotATrip
		}
		return nil, fmt.Errorf("honeypot: store sorgusu basarisiz: %w", err)
	}
	if tool.RevokedAt != nil {
		return nil, trap.ErrNotATrip
	}

	raw, err := json.Marshal(inv)
	if err != nil {
		return nil, fmt.Errorf("honeypot: raw marshal hatasi: %w", err)
	}

	return &trap.TripEvent{
		EventID:    d.idFn(),
		TrapID:     tool.ID,
		Sensor:     obs.Sensor,
		Source:     inv.AgentID,
		ObservedAt: obs.ObservedAt,
		Raw:        raw,
	}, nil
}

// parseInvocation, RawObservation.Line'daki JSON'u Invocation'a çevirir.
// Sensörün (MCP proxy) çağrıyı bu şekilde serialize ettiği varsayılır.
func parseInvocation(obs trap.RawObservation) (*Invocation, error) {
	var inv Invocation
	if err := json.Unmarshal([]byte(obs.Line), &inv); err != nil {
		return nil, err
	}
	if inv.ToolName == "" {
		return nil, errors.New("tool_name bos olamaz")
	}
	return &inv, nil
}
