package config

import "testing"

func TestLoad_MissingDBDSN(t *testing.T) {
	t.Setenv("DB_DSN", "")
	t.Setenv("RECEIPT_SEED_HEX", "seed")
	if _, err := Load(); err == nil {
		t.Fatal("DB_DSN bos iken hata bekleniyordu")
	}
}

func TestLoad_MissingReceiptSeed(t *testing.T) {
	t.Setenv("DB_DSN", "postgres://x/y")
	t.Setenv("RECEIPT_SEED_HEX", "")
	if _, err := Load(); err == nil {
		t.Fatal("RECEIPT_SEED_HEX bos iken hata bekleniyordu")
	}
}

func TestLoad_Defaults(t *testing.T) {
	t.Setenv("DB_DSN", "postgres://x/y")
	t.Setenv("RECEIPT_SEED_HEX", "seed")
	t.Setenv("HTTP_ADDR", "")
	t.Setenv("PROXY_ADDR", "")
	t.Setenv("NATS_URL", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if cfg.HTTPAddr != ":8090" {
		t.Errorf("HTTPAddr = %q, istenen :8090", cfg.HTTPAddr)
	}
	if cfg.ProxyAddr != ":8091" {
		t.Errorf("ProxyAddr = %q, istenen :8091", cfg.ProxyAddr)
	}
	if cfg.NATSURL != "nats://localhost:4222" {
		t.Errorf("NATSURL = %q, istenen varsayilan", cfg.NATSURL)
	}
}

func TestLoad_AllPresent(t *testing.T) {
	t.Setenv("DB_DSN", "postgres://x/y")
	t.Setenv("RECEIPT_SEED_HEX", "seed")
	t.Setenv("HTTP_ADDR", ":9999")
	t.Setenv("PROXY_ADDR", ":9998")
	t.Setenv("NATS_URL", "nats://custom:4222")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if cfg.HTTPAddr != ":9999" || cfg.ProxyAddr != ":9998" || cfg.NATSURL != "nats://custom:4222" || cfg.DBDSN != "postgres://x/y" {
		t.Errorf("cfg = %+v", cfg)
	}
	if cfg.ReceiptSeedHex != "seed" {
		t.Errorf("ReceiptSeedHex = %q, istenen seed", cfg.ReceiptSeedHex)
	}
}
