// Package config, GÖKKALKAN'ın ortam değişkeni tabanlı ayarlarını yükler.
//
// Bilinçli olarak dar tutuldu: bu, GKO-1 (proje iskeleti) kapsamı — proxy'nin
// allowlist/politika ayarları GK-A'nın güvenlik tasarımının parçası, burada
// tanımlanmaz.
package config

import (
	"fmt"
	"os"
)

// Config, çekirdek boot için gereken minimum ayardır.
type Config struct {
	HTTPAddr string
	DBDSN    string
	NATSURL  string
}

// Load, ortam değişkenlerinden Config üretir. DB_DSN zorunludur.
func Load() (Config, error) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		return Config{}, fmt.Errorf("config: DB_DSN zorunlu")
	}

	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8090"
	}

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://localhost:4222"
	}

	return Config{HTTPAddr: addr, DBDSN: dsn, NATSURL: natsURL}, nil
}
