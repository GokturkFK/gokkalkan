// Package config, GÖKKALKAN'ın ortam değişkeni tabanlı ayarlarını yükler.
package config

import (
	"fmt"
	"os"
)

// Config, çekirdek boot için gereken minimum ayardır.
type Config struct {
	HTTPAddr      string
	ProxyAddr     string
	DBDSN         string
	NATSURL       string
	ReceiptSeedHex string
}

// Load, ortam değişkenlerinden Config üretir. DB_DSN ve RECEIPT_SEED_HEX
// zorunludur — receipt.NewSignerFromSeed imzalama anahtarı olmadan hiçbir
// dış çağrı değerlendirilemez (mediator fail-closed disiplini).
func Load() (Config, error) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		return Config{}, fmt.Errorf("config: DB_DSN zorunlu")
	}

	seedHex := os.Getenv("RECEIPT_SEED_HEX")
	if seedHex == "" {
		return Config{}, fmt.Errorf("config: RECEIPT_SEED_HEX zorunlu")
	}

	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8090"
	}

	proxyAddr := os.Getenv("PROXY_ADDR")
	if proxyAddr == "" {
		proxyAddr = ":8091"
	}

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://localhost:4222"
	}

	return Config{
		HTTPAddr:       addr,
		ProxyAddr:      proxyAddr,
		DBDSN:          dsn,
		NATSURL:        natsURL,
		ReceiptSeedHex: seedHex,
	}, nil
}
