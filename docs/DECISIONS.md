# GK-S0 · Sprint 0 tasarım kararları

> **Durum:** öneri — @fetihcakmak onaylayınca kesinleşir (issue #1).
> DevOps tarafı bloke olmasın diye somut bir başlangıç noktası olarak yazıldı;
> nihai söz güvenlik çekirdeğinin sahibinde. Değiştirirsen bu dosyayı güncelle,
> `internal/`'daki kod ve `migrations/` ona göre şekillenir.

GÖKKALKAN'da wire contract zaten donuk (`gokturk-core` v0.1.0). Geriye bu ürüne
özgü iki karar kalıyor.

---

## Karar 1 — Teknik eşlemesi (`correlate.Evaluate(trips, technique)`)

### Neden ATT&CK değil ATLAS

GÖKTÜRK'te `T1078 (Valid Accounts)` kullandık; klasik ATT&CK oraya oturuyordu
çünkü saldırgan çalınmış bir kimlik bilgisiyle SSH'a giriyordu. Agent/MCP
saldırıları klasik ATT&CK matrisinde karşılıksız — bunun için MITRE'nin AI'ya
özel matrisi **ATLAS** var. Aşağıdaki ID'ler ATLAS'ın resmî veri deposundan
(`mitre-atlas/atlas-data`, sürüm **2026.07**) doğrulandı.

### Öneri: tek bir sabit teknik değil, trip kaynağına göre iki teknik

`Evaluate` teknik parametresini bilerek dışarıdan alıyor (core'a çıkarılırken
T1078 sabit kodluydu, parametreye çevrildi). GÖKKALKAN'ın iki farklı tespit
yolu var ve bunlar farklı adversary davranışlarını temsil ediyor:

| Tespit | Teknik | Gerekçe |
|---|---|---|
| **GK-B**: agent honeypot tool'u çağırdı | **`AML.T0053`** — AI Agent Tool Invocation | ATLAS tanımı birebir: *"AI agents may be configured to have access to tools that are not directly accessible by users. Adversaries may abuse this to gain access to tools they otherwise wouldn't be able to use."* Gözlemlediğimiz şey tam olarak bu: agent'ın meşru işi olmayan bir tool'u çağırması. |
| **GK-A2**: zehirli tool açıklaması tespit edildi | **`AML.T0110.000`** — AI Agent Tool Poisoning: Definition and Instructions | ATLAS tanımı: *"Adversaries may poison a tool's model-visible semantic interface, including its descriptions, schemas, parameter documentation, annotations, or agent-readable instructions."* Tool poisoning senaryosunun ders kitabı karşılığı. |

**Neden GK-B'ye `AML.T0110` değil de `AML.T0053`?** Tuzağı biz koyduk; ortada
zehirlenmiş bir tool yok. Gözlemlenen olay, agent'ın yetkisi olmayan bir tool'u
*çağırması*. GÖKTÜRK'teki mantığın aynısı: orada da alarmın tekniği kimliğin
nasıl çalındığı (kök neden) değil, **çalınan kimlikle ne yapıldığı** (gözlenen
davranış) üzerinden seçilmişti.

### İkincil eşlemeler (tehdit modeline, alarm alanına değil)

- **`AML.T0051.001`** — LLM Prompt Injection: Indirect. Zehirlenme harici bir
  veri kanalından geldiyse kök neden budur. Alarmda taşınmaz; GK-F1 tehdit
  modelinde anlatılır.
- **`AML.T0110.001` / `AML.T0110.002`** — Implementation / Runtime Response.
  v0.1'de tespit etmiyoruz (sadece `.000`, yani açıklama/şema düzeyi).
- **OWASP**: `LLM01:2025 Prompt Injection` (GenAI Security Project). OWASP
  Agentic taksonomisiyle eşleme GK-F1'in işi.

### Kodda karşılığı

```go
const (
    TechniqueToolInvocation = "AML.T0053"     // honeypot tool cagrildi
    TechniqueToolPoisoning  = "AML.T0110.000" // zehirli tool aciklamasi
)

alerts := correlate.Evaluate(trips, TechniqueToolInvocation)
```

Panelin teknik sütunu şu an `^T\d{4}(\.\d{3})?$` regex'iyle ATT&CK linki
üretiyor (`dashboard/app.py`). ATLAS ID'leri bu desene uymaz — panel tarafında
ATLAS linki (`https://atlas.mitre.org/techniques/<ID>`) için ayrı bir dal
gerekecek. Bu **GKO-4'ün işi**, GK-A/GK-B'yi bloklamaz.

---

## Karar 2 — Agent kimlik / allowlist / honeypot şeması

`migrations/00001_init.sql` bilerek sadece `trip_events` + `alerts` içeriyor.
Aşağıdaki öneri onaylanınca `00002_agents.sql` olarak eklenecek (GKO-6, issue #6).

```sql
-- Agent kimligi. Secret'in kendisi DB'de tutulmaz; GOKTURK'teki
-- traps.secret_hash deseninin aynisi (HMAC_KEY ile imzali ozet).
CREATE TABLE agents (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text NOT NULL UNIQUE,      -- "ci-deploy-agent"
    token_hash   text NOT NULL,             -- HMAC-SHA256(token)
    created_at   timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz                -- enforcement: dolu ise agent kesik
);

-- Deny-by-default: burada SATIRI OLMAYAN her cagri reddedilir.
CREATE TABLE agent_allowlist (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id     uuid NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    method       text NOT NULL DEFAULT '*', -- GET / POST / *
    host         text NOT NULL,             -- api.github.com
    path_prefix  text NOT NULL DEFAULT '/',
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, method, host, path_prefix)
);

-- Sahte MCP tool tanimlari = tuzak. id, TripEvent.TrapID olarak tasinir.
CREATE TABLE honeypot_tools (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text NOT NULL UNIQUE,      -- agent'in gordugu tool adi
    description  text NOT NULL,             -- "inandirici" aciklama (GK-B1)
    input_schema jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by   text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz
);
```

Ardından `trip_events.trap_id` (şu an düz metin) `honeypot_tools(id)`'ye FK
yapılabilir.

### Gerekçeler

- **Kimlik = token, mTLS değil.** GÖKTÜRK'te de mTLS (OPS-9) v0.1 kapsamı
  dışına alınmıştı; aynı yargı. Token yeterli, sonra sertleştirilir.
- **Token düz metin saklanmaz.** `traps.secret_hash` deseni: HMAC özeti tutulur,
  DB sızsa bile token geri elde edilemez.
- **Allowlist ayrı tablo.** JSON kolonu yerine satır — çünkü enforcement sıcak
  yolda sorgulanacak ve `UNIQUE` kısıtı çift kayıt riskini DB seviyesinde keser
  (OPS-11'deki partial-unique-index disiplininin aynısı).
- **`revoked_at` enforcement'ın kendisi.** Critical alarmda GKO-2 bu alanı
  doldurur; proxy her istekte kontrol eder. Ayrı bir "kesik agent" tablosuna
  gerek yok.

### Bu şemanın DEĞİŞTİRİLMESİ gereken yerler (senin kararın)

- `honeypot_tools.description`'ın nasıl "inandırıcı" olacağı — GK-B1'in
  tespit-edilemezlik işi. Kolon yapısı değil, **içeriği** senin alanın.
- Allowlist'in granülaritesi host/path yeterli mi, yoksa MCP tool adı
  seviyesinde mi olmalı? Proxy'nin gerçekte neyi gördüğüne bağlı (GK-A1).

---

## Referanslar

- MITRE ATLAS resmî veri: https://github.com/mitre-atlas/atlas-data (`dist/v6/ATLAS-2026.07.yaml`)
- ATLAS teknik sayfaları: https://atlas.mitre.org/techniques/AML.T0053 · https://atlas.mitre.org/techniques/AML.T0110
- OWASP LLM01:2025 Prompt Injection: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
