# Demo GIF senaryosu (issue #5, GK-F1)

> DoD madde 5'in son parçası. GÖKTÜRK'teki yöntem (Playwright frame capture)
> burada uygulanmıyor — GÖKKALKAN'ın "arayüzü" bir web sayfası değil, bir
> egress proxy + JSON API. Terminal ekran kaydı (asciinema, ScreenToGif,
> macOS'ta Kap, ya da düz `ffmpeg -f gdigrab`) yeterli; aşağıdaki adımları
> sırayla çalıştırıp kaydetmek `docs/demo.gif`'i üretir.

> **Durum: koşuldu ve doğrulandı.** Altı adım da gerçek yığına karşı
> çalıştırıldı; çıktıları `docs/demo.gif`'te. Bu koşu bir hata ortaya
> çıkardı: adım 2 (meşru çağrı) 502 dönüyordu, çünkü agent'ların
> gönderdiği origin-form istekte `r.URL.Host` boştur ve `ReverseProxy`
> hedefi kuramıyordu (#27 ile düzeltildi). Yani bu script'in kendisi bir
> test görevi gördü — birim testleri `httptest.NewRequest`'i mutlak url
> ile kurduğu için bu hatayı görememişti.

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

$PSQL -c "INSERT INTO agents (name, token_hash) VALUES ('demo-agent', 'demo-hash');"

# id'yi ayri bir SELECT ile al. `INSERT ... RETURNING id` ciktisini dogrudan
# degiskene almak calismaz: -tA modunda bile sonuna "INSERT 0 1" komut
# etiketi eklenir ve agent_id gecersiz uuid olur.
AGENT_ID=$($PSQL -tAc "SELECT id FROM agents WHERE name='demo-agent';")
echo "$AGENT_ID"
```

> `psql` kurulu değilse ayni komutlar container icinden calisir:
> `docker exec -i gokkalkan-postgres-1 psql -qtAX -U gokkalkan -d gokkalkan -c "..."`

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

✅ Yapıldı: [`docs/demo.gif`](demo.gif), README'de gömülü.

Kayıttaki her satır yukarıdaki komutların gerçek çıktısıdır (agent id,
imza önekleri ve `octocat/Hello-World` yanıtı o koşudan). Yeniden üretmek
için adım 2-6'yı sırayla, çıktıları ekranda bırakarak çalıştırıp kaydet.

Doğrulanan davranış:

| Adım | Beklenen | Gerçekleşen |
|---|---|---|
| 2 | meşru çağrı engelsiz geçer | `HTTP 200`, gerçek `api.github.com` yanıtı |
| 3 | yetkisiz çağrı reddedilir | 2× `HTTP 403`, 2.'de agent kesildi |
| 4 | panelde Critical | `Critical` / `AML.T0053` / `trip_count=2` |
| 5 | kesilen agent meşru hedefe de çıkamaz | `HTTP 403` (`agent kesilmis`) |
| 6 | her çağrının imzalı kaydı | 4 receipt, **4/4 imza Ed25519 ile doğrulandı** |

Adım 6'daki doğrulama ayrı bir kontroldü: receipt'ler `Postgres → JSON →
HTTP` yolculuğundan sonra da `receipt.Verify`'dan geçiyor, yani
imzalamadaki mikrosaniye normalizasyonu serileştirmeyi sağ atlatıyor.

## Temizlik

```sh
make docker-down
```
