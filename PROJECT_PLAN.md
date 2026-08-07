# GÖKKALKAN — Agentic AI Runtime Security · Görev Planı

> İki kişilik ekip için hazırlanmış, board'a doğrudan taşınabilir görev dökümü.
> **Cyber** (`@fetihcakmak`) = güvenlik çekirdeği: agent egress proxy'nin tespit/politika
> mantığı, agent honeypot tuzakları, tehdit modeli.
> **DevOps** (`@uzunkubra50`) = platform, teslimat, ops + korelasyon/enforcement wiring,
> panel, imzalama — GÖKTÜRK'teki sahiplik deseninin aynısı (bkz. `gokturk-deception-mesh/PROJECT PLAN.md` böl. 5).
>
> Bu, Göktürk platformunun ikinci ürünüdür; ilki
> [GÖKTÜRK](https://github.com/GokturkFK/gokturk-deception-mesh) (deception mesh).
> Platform kuralı: **aynı anda tek aktif ürün** — bir ürün kendi DoD'sine
> ulaşmadan sonraki başlatılmaz.
>
> **Ön koşul geçildi:** GÖKTÜRK v0.1 DoD tamamlandı ve ortak omurga
> [gokturk-core](https://github.com/GokturkFK/gokturk-core) `v0.1.0` olarak
> ayrıldı (`trap.Provider`, `TripEvent`/`Alert` şeması, `correlate.Evaluate`).
> GÖKKALKAN onu import eder, kopyalamaz.

---

## 1. Milestone hedefi (tek cümle)

Zehirli bir tool açıklamasıyla (tool poisoning / goal hijack) yetkisiz bir uca
bağlanmaya çalışan bir AI agent, **egress proxy tarafından kesilir**; panelde
**Critical** alarm + **imzalı action receipt** üretilir — meşru bir tool çağrısı
ise **hiçbir engelle karşılaşmaz** (sıfır-FP, GÖKTÜRK ile aynı tez, yeni yüzey).

---

## 2. Kapsam (v0.1 — roadmap'teki GK-A..GK-E)

**Dahil:**
- Tek enforcement noktası: MCP/HTTP çağrılarını arayan **egress proxy**, per-agent
  deny-by-default allowlist.
- Tek tuzak türü: **agent honeypot** (sahte MCP tool / sahte tool açıklaması) —
  `gokturk-core/trap.Provider`'ın yeni bir uygulaması.
- Tuzak tetiklenince: `gokturk-core/trap.TripEvent` → `gokturk-core/correlate.Evaluate`
  (technique: GÖKKALKAN'a özgü, APP-11 muadili tehdit modelinde netleşecek) → alarm.
- Alarm → proxy'nin o agent kimliğini **otomatik kesmesi** (alarm değil, aksiyon).
- Her dış çağrı için **imzalı action receipt** (denetlenebilir kanıt).
- Aynı SOC panelinin agent olaylarını da göstermesi (GÖKTÜRK panelinin uzantısı).

**Hariç (bilinçli ertelendi):**
- Birden çok agent framework'ü için native SDK entegrasyonu → sadece MCP/HTTP
  proxy seviyesi, v0.1'de tek entegrasyon yüzeyi.
- NHI/blast-radius grafiği → P3 (GÖKZİNCİR).
- Ayrı korelasyon servisi → P4, GÖKKALKAN'da korelasyon `gokturk-core` içinde in-process kalır.

---

## 3. Önce sözleşmeleri doğrula (Sprint 0)

GÖKTÜRK'ten farklı olarak wire contract sıfırdan yazılmıyor —
`gokturk-core` zaten donuk: `trap.Provider`, `trap.TripEvent`, `correlate.Alert`,
`correlate.Evaluate(trips, technique)`. Sprint 0'da netleşmesi gereken tek şey:

- **GÖKKALKAN'a özgü ATT&CK/OWASP Agentic teknik kodu** — `correlate.Evaluate`'e
  hangi `technique` string'i geçilecek (APP-11 muadili, Cyber'in tehdit modeli
  kararı).
- **Agent kimlik/allowlist şeması** (Postgres) — hangi agent'in hangi endpoint'e
  izinli olduğu; honeypot tool tanımlarının şekli. Bu, GK-A/GK-B'nin güvenlik
  tasarımının parçası, DevOps bunu önceden dondurmaz.

Bu iki karar netleşmeden GK-A/GK-B kod yazımı başlamaz (GÖKTÜRK'teki "önce
sözleşmeleri dondur" kuralının aynısı).

> **Somut öneri hazır:** [docs/DECISIONS.md](docs/DECISIONS.md) — teknik eşlemesi
> için `AML.T0053` / `AML.T0110.000` (MITRE ATLAS 2026.07'den doğrulanmış) ve
> agent/allowlist/honeypot şeması taslağı. @fetihcakmak onaylayınca kesinleşir
> (issue #1); değişirse o dosya güncellenir.

---

## 4. Görevler — CYBER (güvenlik çekirdeği)

> Sahiplik kuralı GÖKTÜRK ile birebir aynı: `@fetihcakmak` yalnızca tuzak/tespit
> mantığını ve tehdit modelini yürütür; geri kalan her şey `@uzunkubra50`'de.

### EPIC GK-A — Agent egress proxy
- **GK-A1 · MCP/HTTP interception + deny-by-default allowlist** — proxy'nin
  çekirdek karar mantığı: per-agent izin listesi, varsayılan red.
  - *Sahip:* @fetihcakmak
  - *AC:* Allowlist'te olmayan bir endpoint'e çağrı → engellenir; allowlist'teki
    çağrı → hiç gecikme/engel olmadan geçer.
  - *Dep:* Sprint 0 (agent kimlik/allowlist şeması)
- **GK-A2 · Jailbreak/prompt-injection sinyali** — zehirli bir tool açıklaması
  veya prompt-injection denemesiyle allowlist dışı bir uca yönelme girişiminin
  tespiti.
  - *Sahip:* @fetihcakmak
  - *AC:* Zehirli tool açıklaması içeren bir test senaryosu → proxy tespit edip
    engelliyor + `TripEvent` üretiyor.

### EPIC GK-B — Agent honeypot tuzakları
- **GK-B1 · Sahte MCP tool / tool açıklaması provider'ı** — `gokturk-core/trap.Provider`'ı
  uygulayan yeni bir tuzak türü: gerçek bir tool gibi görünen ama dokunulunca
  `TripEvent` üreten sahte MCP tool tanımı.
  - *Sahip:* @fetihcakmak
  - *AC:* Bir agent bu tool'u çağırdığında `trip.events.v1`'e doğru `TripEvent`
    düşüyor; meşru tool çağrıları hiçbir şey tetiklemiyor (sıfır-FP).
  - *Dep:* `gokturk-core/trap.Provider`

### EPIC GK-F — Tehdit modeli
- **GK-F1 · Tehdit modeli & framework mapping** — NSA MCP güvenlik rehberi +
  OWASP Agentic Top 10 eşlemesi, README mimari bölümü, demo GIF.
  - *Sahip:* @fetihcakmak
  - *AC:* README'de mimari diyagram + tehdit modeli + demo GIF (GÖKTÜRK APP-11 muadili).

---

## 5. Görevler — DEVOPS (platform/teslimat/ops + wiring)

> *Sahip:* Bu bölümdeki tüm görevler `@uzunkubra50`.

### EPIC GK-C — Deception-tetikli enforcement (wiring)
- **GKO-1 · Proje iskeleti & config** — `cmd/gokkalkan`, ortam değişkeni tabanlı
  config, graceful shutdown, `/healthz`. **(tamamlandı, bkz. commit geçmişi)**
  - *AC:* `go run ./cmd/gokkalkan` boot oluyor, `/healthz` 200 dönüyor.
- **GKO-2 · Korelasyon + enforcement entegrasyonu** — GK-A/GK-B'nin ürettiği
  `TripEvent`'i `gokturk-core/correlate.Evaluate`'e besle, Critical alarmda
  proxy'ye "bu agent kimliğini kes" komutunu ver.
  - *AC:* Tuzak tetiklenince ≤5 sn içinde agent kimliği kesiliyor + panelde Critical.
  - *Dep:* GK-A1, GK-B1

### EPIC GK-D — İmzalı action receipt
- **GKO-3 · Action receipt imzalama** — her dış çağrıyı mediator olarak
  imzalayan bileşen (OPS-4'teki cosign/SBOM desenine paralel, aynı imzalama
  disiplini).
  - *AC:* Her dış çağrı için doğrulanabilir imzalı bir receipt üretiliyor.

### EPIC GK-E — Panel entegrasyonu
- **GKO-4 · Dashboard'a agent feed'i** — GÖKTÜRK panelinin `GET /api/v1/alerts`
  akışına agent olaylarını da düşür (aynı feed, aynı severity/teknik kolonları).
  - *AC:* Agent tuzağı tetiklenince aynı panelde ≤5 sn içinde görünür.
  - *Dep:* GKO-2

### EPIC GK-G — Repo & CI/CD
- **GKO-5 · Repo hijyeni + CI** — `gokturk-deception-mesh` ile aynı desen:
  build/vet/test/lint, branch protection, squash-only. **(tamamlandı)**
- **GKO-6 · DB migration iskeleti** — `trip_events`/`alerts` şeması (gokturk-core
  ile aynı şekil); agent-kimlik/allowlist/honeypot tabloları GK-A/GK-B'nin
  tasarımı netleşince eklenir (DevOps bunu önceden dondurmaz).
  - *AC:* `make migrate-up/down` çalışıyor.

---

## 6. Definition of Done (v0.1)

Aşağıdakilerin **hepsi** doğruysa GÖKKALKAN v0.1 biter:

1. Zehirli bir tool açıklamasıyla bir test agent'ı attacker endpoint'ine
   bağlanmaya kalkar → proxy keser.
2. Aynı anda: panelde **Critical** alarm + imzalı action receipt üretilir.
3. Meşru bir tool çağrısı → hiçbir engel, hiçbir alarm (sıfır-FP).
4. `go test ./... -race` yeşil, çekirdek kapsam ≥ %70.
5. README: mimari diyagram + tehdit modeli (NSA MCP rehberi/OWASP Agentic) + demo GIF.
6. CI PR'ı bloklayabiliyor.

---

## 7. Riskler & kilit noktalar

- **Kontrat kayması:** `gokturk-core`'daki `TripEvent`/`Alert` şekli değişirse
  hem GÖKTÜRK hem GÖKKALKAN aynı anda kırılır → değişiklik ancak version bump.
- **Kapsam sürünmesi:** roadmap'in P2 DoD'si kilitli; NHI/graph (P3) veya ayrı
  korelasyon servisi (P4) buraya sızmaz.
- **Sıfır-FP korunmalı:** GK-A2'nin jailbreak tespiti agresifleşirse meşru tool
  çağrıları da engellenebilir — GÖKTÜRK'teki "bilinçli olarak ML/anomali yok"
  ilkesiyle aynı disiplin burada da geçerli.
