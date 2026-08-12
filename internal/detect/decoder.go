package detect

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/GokturkFK/gokturk-core/trap"
)

// Invocation, bir agent'ın bir tool'u cagirma/gorme anindaki ham
// gozlemidir. Sensor (proxy/MCP interceptor) tool tanimini bu sekilde
// serialize eder.
type Invocation struct {
	AgentID     string   `json:"agent_id"`
	ToolName    string   `json:"tool_name"`
	Description string   `json:"description"`
	ParamDocs   []string `json:"param_docs,omitempty"`
	Annotations []string `json:"annotations,omitempty"`
}

// Decoder, gokturk-core/trap.Decoder'ı uygular: bir tool tanımının
// zehirlenmiş olup olmadığına Scan ile bakar. Eşleşme yoksa
// trap.ErrNotATrip döner — meşru tool tanımları hiçbir event üretmez
// (sıfır-FP, issue #3 AC 2).
type Decoder struct {
	idFn func() string
}

// NewDecoder, verilen idFn ile bir Decoder kurar. idFn zorunludur
// (örn. production'da google/uuid.NewString).
func NewDecoder(idFn func() string) *Decoder {
	return &Decoder{idFn: idFn}
}

// Decode, gokturk-core/trap.Decoder sözleşmesini karşılar.
func (d *Decoder) Decode(obs trap.RawObservation) (*trap.TripEvent, error) {
	if d.idFn == nil {
		return nil, errors.New("detect: idFn tanimli degil")
	}

	var inv Invocation
	if err := json.Unmarshal([]byte(obs.Line), &inv); err != nil {
		return nil, fmt.Errorf("detect: gozlem cozumlenemedi: %w", err)
	}
	if inv.ToolName == "" {
		return nil, errors.New("detect: tool_name bos olamaz")
	}

	finding := Scan(ToolDescription{
		ToolName:    inv.ToolName,
		Description: inv.Description,
		ParamDocs:   inv.ParamDocs,
		Annotations: inv.Annotations,
	})
	if !finding.Matched {
		return nil, trap.ErrNotATrip
	}

	raw, err := json.Marshal(struct {
		Invocation
		Pattern string `json:"matched_pattern"`
		Field   string `json:"matched_field"`
	}{inv, finding.Pattern, finding.Field})
	if err != nil {
		return nil, fmt.Errorf("detect: raw marshal hatasi: %w", err)
	}

	return &trap.TripEvent{
		EventID:    d.idFn(),
		TrapID:     inv.ToolName,
		Sensor:     obs.Sensor,
		Source:     inv.AgentID,
		ObservedAt: obs.ObservedAt,
		Raw:        raw,
	}, nil
}
