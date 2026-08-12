# GÖKKALKAN — Tehdit Modeli

> GK-F1 (issue #5). GÖKTÜRK'teki APP-11'in muadili: NSA MCP güvenlik
> rehberi ve OWASP Agentic Top 10 (GenAI Security Project) ile eşleme +
> kısa bir STRIDE tablosu. Teknik kod kararları için bkz.
> [docs/DECISIONS.md](DECISIONS.md); mimari diyagram için
> [README.md](../README.md#mimari).

## Kapsam

GÖKKALKAN, bir AI agent'ın MCP/HTTP üzerinden yaptığı **dış çağrıları**
denetler. Tehdit modeli iki senaryoya odaklanır:

1. Agent, **yetkisi olmayan bir uca** bağlanmaya çalışır (allowlist dışı).
2. Agent'ın gördüğü bir **tool tanımı zehirlenmiş** — açıklama/parametre
   dokümantasyonu, agent'ı istenmeyen bir davranışa yönlendirmeye çalışıyor
   (tool poisoning / prompt injection).

Kapsam dışı (v0.1, bkz. PROJECT_PLAN.md böl. 2): çoklu framework SDK
entegrasyonları, NHI/blast-radius grafiği, ayrı korelasyon servisi.

## NSA/CISA MCP Güvenlik Rehberi Eşlemesi

NSA/CISA'nın "Deploying AI Systems Securely" ve MCP'ye özgü rehberlik
notlarındaki üç temel öneri, GÖKKALKAN'da şu bileşenlere karşılık gelir:

| NSA/CISA önerisi | GÖKKALKAN karşılığı |
|---|---|
| Araç/kaynak erişimini en az ayrıcalık ilkesiyle sınırla | `internal/proxy`: per-agent deny-by-default allowlist (`agent_allowlist`, method/host/path_prefix) |
| Araç açıklamalarının/şemalarının bütünlüğünü doğrula | `internal/detect`: tool açıklaması + parametre dokümantasyonu + annotasyonlar, deterministik desenlere karşı taranır |
| Anomali/kötüye kullanımı denetlenebilir şekilde logla | `gokturk-core/trap.TripEvent` + `correlate.Evaluate` → `Alert`; GKO-3'te imzalı receipt (henüz yazılmadı) |

## OWASP Agentic Top 10 Eşlemesi

OWASP GenAI Security Project'in Agentic AI tehdit taksonomisinden,
GÖKKALKAN'ın kapsadığı maddeler:

| OWASP Agentic risk | Açıklama | GÖKKALKAN kontrolü |
|---|---|---|
| Tool Misuse / Excessive Agency | Agent, kendisine tanınmayan bir tool'u veya endpoint'i kullanır | `internal/proxy.Enforcer.Evaluate` — deny-by-default |
| Tool Poisoning | Tool'un model-görünür arayüzü (açıklama, şema, parametre dokümantasyonu) zehirlenir | `internal/detect.Scan` — 6 deterministik desen (ignore-instructions, credential exfiltration, vb.) |
| Prompt Injection (dolaylı) | Zehirlenme harici bir veri kanalından (tool açıklaması) gelir | Aynı `internal/detect.Scan`; kök neden OWASP LLM01:2025 ile örtüşür |
| Insufficient Monitoring/Auditability | Agent olaylarının denetlenebilir kaydı yok | `trap.TripEvent` (wire contract, `trip.events.v1`) + GKO-3 imzalı receipt |

**Bilinçli olarak kapsam dışı:** Goal Manipulation, Multi-Agent Collusion,
Resource Exhaustion — bunlar GÖKKALKAN'ın proxy-katmanı enforcement
modeliyle doğrudan gözlemlenemez, P3/P4 roadmap'ine (NHI/blast-radius,
ayrı korelasyon servisi) bırakıldı.

## STRIDE Tablosu

| Kategori | Tehdit | Etkilenen bileşen | Kontrol |
|---|---|---|---|
| **S**poofing | Sahte/çalıntı agent kimliğiyle çağrı yapma | `internal/proxy` | `agents.token_hash` (HMAC, düz metin saklanmaz); `revoked_at` ile anlık kesme |
| **T**ampering | Tool açıklamasının/şemasının çalışma zamanında değiştirilmesi | `internal/detect` | Her çağrıda yeniden tarama (statik önbellek yok); `honeypot_tools` sürüm/revoke alanı |
| **R**epudiation | Agent'ın "ben bu çağrıyı yapmadım" demesi | `gokturk-core/trap.TripEvent`, GKO-3 | İmzalı action receipt (GKO-3, henüz yazılmadı) — hedef budur |
| **I**nformation Disclosure | Zehirli tool aracılığıyla credential/secret sızdırma | `internal/detect` | `exfiltrate-credentials` deseni; `trap.Trap.SecretHash` API cevabına asla çıkmaz |
| **D**enial of Service | Agent'ın allowlist'i zorlayarak proxy'yi meşgul etmesi | `internal/proxy` | Deny-by-default O(allowlist) arama; rate-limiting kapsam dışı (v0.1) |
| **E**levation of Privilege | Tool açıklaması aracılığıyla "kendine admin yetkisi ver" talimatı | `internal/detect` | `self-referential-elevation` deseni |

## Bilinçli Tasarım Kararları (sıfır-FP disiplini)

- **ML/anomali tespiti yok.** Hem `internal/proxy` (allowlist eşleşmesi)
  hem `internal/detect` (regex desenleri) tamamen deterministiktir.
  Olasılıksal bir sınıflandırıcı, meşru tool açıklamalarını da
  engelleyebilir — PROJECT_PLAN.md'deki "sıfır-FP ancak deterministik
  kurallarla savunulabilir" ilkesi.
- **Emin olunmayan durumda reddet.** Agent bulunamadı, revoked, store
  hatası → hepsi `Allowed: false`. GÖKTÜRK'teki `ErrNotATrip`
  disiplininin proxy tarafındaki karşılığı.
- **Parser-differential'a karşı savunma.** `internal/proxy`, path
  karşılaştırmasını hem segment-sınırlı hem encode-edilmiş metakarakterlere
  (`%2e`, `%5c` vb.) karşı reddederek yapar — enforcement katmanının
  gördüğü path ile gerçek transport'un yorumladığı path arasındaki
  farktan doğan bypass'ları kapatır.

## Bilinen Sınırlar / Gelecek İş

- Demo GIF (issue #5'in üçüncü teslimatı) GKO-2 (korelasyon→enforcement
  wiring) tamamlanana kadar eklenemez — proxy/honeypot/detect şu an ayrı
  Go paketleri, tek bir çalışan binary'de henüz birbirine bağlı değil.
- Rate-limiting / DoS koruması v0.1 kapsamı dışında (yukarıdaki STRIDE
  tablosunda not edildi).
- mTLS tabanlı agent kimliği v0.1'de yok (token yeterli görüldü,
  `docs/DECISIONS.md` Karar 2 gerekçesi).
