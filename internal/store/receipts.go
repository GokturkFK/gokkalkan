package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/GokturkFK/gokkalkan/internal/receipt"
)

// ErrReceiptIDRequired, imzasız/kimliksiz bir receipt yazılmaya
// çalışıldığında döner.
var ErrReceiptIDRequired = errors.New("store: receipt ID'si bos — kimlik IMZADAN ONCE uretilmeli")

// InsertReceipt, imzalı bir action receipt'i kalıcı yazar (GKO-3).
//
// Receipt.ID ZORUNLUDUR ve imzalanmadan önce üretilmiş olmalıdır: ID imza
// kapsamındadır, DB'nin üretmesine bırakılırsa imza boş ID üzerinden
// hesaplanır, kayıtta ID dolu olur ve geri okunan kanıt hiçbir zaman
// doğrulanmaz. Sessizce doğrulanamaz kanıt üretmektense burada patlar.
func (s *Store) InsertReceipt(ctx context.Context, sr receipt.SignedReceipt) (string, error) {
	if sr.ID == "" {
		return "", ErrReceiptIDRequired
	}

	var id string
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO action_receipts (id, agent_id, method, host, path, allowed, reason, issued_at, key_id, signature)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
		sr.ID, sr.AgentID, sr.Method, sr.Host, sr.Path, sr.Allowed, sr.Reason, sr.IssuedAt, sr.KeyID, sr.Signature,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("store: receipt yazilamadi: %w", err)
	}
	return id, nil
}

// ReceiptsByAgent, bir agent'ın receipt'lerini en yeni önce döner (denetim).
func (s *Store) ReceiptsByAgent(ctx context.Context, agentID string, limit int) ([]receipt.SignedReceipt, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id::text, agent_id, method, host, path, allowed, reason, issued_at, key_id, signature
		 FROM action_receipts WHERE agent_id = $1 ORDER BY issued_at DESC LIMIT $2`,
		agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: receipt'ler okunamadi: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []receipt.SignedReceipt
	for rows.Next() {
		var sr receipt.SignedReceipt
		if err := rows.Scan(&sr.ID, &sr.AgentID, &sr.Method, &sr.Host, &sr.Path,
			&sr.Allowed, &sr.Reason, &sr.IssuedAt, &sr.KeyID, &sr.Signature); err != nil {
			return nil, fmt.Errorf("store: receipt satiri okunamadi: %w", err)
		}
		out = append(out, sr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: receipt iterasyonu: %w", err)
	}
	return out, nil
}
