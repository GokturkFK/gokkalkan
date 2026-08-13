# Demo GIF senaryosu (issue #5, GK-F1)

> DoD madde 5'in son parçası. GÖKTÜRK'teki yöntem (Playwright frame capture)
> burada uygulanmıyor — GÖKKALKAN'ın "arayüzü" bir web sayfası değil, bir
> egress proxy + JSON API. Terminal ekran kaydı (asciinema, ScreenToGif,
> macOS'ta Kap, ya da düz `ffmpeg -f gdigrab`) yeterli; aşağıdaki adımları
> sırayla çalıştırıp kaydetmek `docs/demo.gif`'i üretir.

## Ön koşul

```sh
cp deployments/docker/.env.example deployments/docker/.env
make docker-up
```

Postgres ayağa kalktıktan sonra (healthcheck yeşil olana kadar bekle),
başka bir terminalde şemayı uygula:

```sh
DB_DSN="postgres://gokkalkan:gokkalkan@localhost:5433/gokkalkan?sslmode=disable" make migrate-up
```

## Senaryo: zehirli tool açıklaması → engellenir → Critical alarm → kesme

Bu, PROJECT_PLAN.md böl. 1'deki milestone cümlesinin bire bir karşılığı.
Aşağıdaki adımlar `psql` ile agent/allowlist kaydı açar, sonra `curl` ile
gerçek bir proxy çağrısı yapar.

**1. Bir agent ve BOŞ allowlist kaydet** (yani her çağrı deny-by-default
reddedilecek — demo'da "meşru çağrı" ile "zehirli çağrı" arasındaki
farkı göstermek için ikinci bir agent'a gerçek bir allowlist satırı da
eklenir):

```sh
PSQL="psql postgres://gokkalkan:gokkalkan@localhost:5433/gokkalkan?sslmode=disable"

$PSQL -c "INSERT INTO agents (name, token_hash) VALUES ('demo-agent', 'demo-hash') RETURNING id;"
# çıktıdaki id'yi kopyala -> $AGENT_ID
```

**2. Meşru çağrı — hiçbir engelle karşılaşmaz** (sıfır-FP, DoD madde 3):

```sh
$PSQL -c "INSERT INTO agent_allowlist (agent_id, method, host, path_prefix) VALUES ('$AGENT_ID','*','api.github.com','/repos');"

curl -i -X GET http://localhost:8091/repos/octocat/hello-world \
  -H "Host: api.github.com" \
  -H "X-Gokkalkan-Agent-Id: $AGENT_ID"
# beklenen: proxy gercek hedefe iletir (api.github.com'a DNS/network varsa
# 200 döner; yoksa bağlantı hatası — ama ÖNEMLİ olan proxy'nin 403
# DÖNDÜRMEMESİ, yani allowlist eşleşmesinin geçtiği)
```

**3. Zehirli/yetkisiz çağrı — engellenir + panelde Critical alarm**
(DoD madde 1-2). Aynı agent, allowlist'te olmayan bir hedefe 2 kez
bağlanmaya çalışır (2. deneme kampanya birleşmesiyle Critical'a yükselir,
GÖKTÜRK'teki "1 trip → High, ≥2 → Critical" tezinin aynısı):

```sh
curl -i -X GET http://localhost:8091/steal \
  -H "Host: evil.example.com" \
  -H "X-Gokkalkan-Agent-Id: $AGENT_ID"
# beklenen: HTTP/1.1 403 Forbidden, {"error":"reddedildi","reason":"..."}

curl -i -X GET http://localhost:8091/steal \
  -H "Host: evil.example.com" \
  -H "X-Gokkalkan-Agent-Id: $AGENT_ID"
# beklenen: yine 403 — ama bu ikinci tetikleme artik Critical alarm
# uretir ve agent'i KESER
```

**4. Panelde Critical alarmı göster** (GÖKTÜRK panelinin aynı feed'i,
GKO-4):

```sh
curl -s http://localhost:8090/api/v1/alerts | jq .
# beklenen: severity="Critical", technique="AML.T0053", trip_count=2
```

**5. Agent'ın gerçekten kesildiğini göster** — artık allowlist'teki meşru
hedefe bile bağlanamaz:

```sh
curl -i -X GET http://localhost:8091/repos/octocat/hello-world \
  -H "Host: api.github.com" \
  -H "X-Gokkalkan-Agent-Id: $AGENT_ID"
# beklenen: 403 (agent revoked, allowlist artik gecerli degil)
```

**6. İmzalı receipt'i göster** (denetlenebilir kanıt, DoD madde 2):

```sh
curl -s "http://localhost:8090/api/v1/receipts?agent_id=$AGENT_ID" | jq .
# beklenen: her cagri icin bir SignedReceipt, signature dolu
```

## Kayıt

Adım 2-6'yı sırayla, her komutun çıktısını ekranda görünür bırakarak
çalıştırıp kaydet (asciinema/ScreenToGif ile). Kayıt bittiğinde
`docs/demo.gif` olarak commit'le ve `README.md`'ye şu satırı ekle:

```markdown
![demo](docs/demo.gif)
```

## Temizlik

```sh
make docker-down
```
