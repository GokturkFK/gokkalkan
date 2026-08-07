# GÖKKALKAN

Agentic AI Runtime Security — MCP/agent egress proxy + agent honeypot deception.
Göktürk platformunun P2'si (bkz. [gokturk-core](https://github.com/GokturkFK/gokturk-core),
[gokturk-deception-mesh](https://github.com/GokturkFK/gokturk-deception-mesh)).
Görev dökümü: [PROJECT_PLAN.md](PROJECT_PLAN.md).

**Tek cümlelik hedef:** Zehirli bir tool açıklamasıyla yetkisiz bir uca
bağlanmaya çalışan bir AI agent, egress proxy tarafından **kesilir**; panelde
Critical alarm + imzalı action receipt üretilir — meşru bir tool çağrısı ise
hiçbir engelle karşılaşmaz.

> Durum: iskelet aşaması. Boot binary + altyapı + CI ayakta (GKO-1, GKO-5);
> proxy'nin interception/allowlist/enforcement mantığı (GK-A, GK-B) henüz
> yazılmadı.

## Nereden başlanır

**Tüm işler [issue](../../issues) olarak açık ve atanmış.** Etiketler:
`cyber` = @fetihcakmak (güvenlik çekirdeği), `devops` = @uzunkubra50
(platform/teslimat/wiring). Hangi dosya kimin: [CODEOWNERS](CODEOWNERS).

| Sıra | Issue | Kim |
|---|---|---|
| **1. ÖNCE BU** | [#1 GK-S0](../../issues/1) — Sprint 0 tasarım kararı (`blocker`) | @fetihcakmak |
| 2 | [#2 GK-A1](../../issues/2) egress proxy · [#4 GK-B1](../../issues/4) agent honeypot | @fetihcakmak |
| 3 | [#3 GK-A2](../../issues/3) jailbreak tespiti | @fetihcakmak |
| 4 | [#6](../../issues/6) migration · [#7](../../issues/7) enforcement wiring | @uzunkubra50 |
| 5 | [#8](../../issues/8) imzalı receipt · [#9](../../issues/9) panel | @uzunkubra50 |
| son | [#5 GK-F1](../../issues/5) tehdit modeli + demo GIF | @fetihcakmak |

#1 bitmeden hiçbir şey başlayamaz (hem GK-A/GK-B hem DevOps wiring ona bağlı).
Somut bir öneri hazır — üstüne "tamam" veya "hayır, şöyle olmalı" demek yeterli:
[docs/DECISIONS.md](docs/DECISIONS.md).

## Mimari

`gokturk-core`'u import eder: `trap.Provider`/`TripEvent` sözleşmesi ve
`correlate.Evaluate` korelasyon motoru GÖKTÜRK ile aynı, kopyalanmaz.

## Geliştirme

```sh
cp deployments/docker/.env.example deployments/docker/.env
make build
make test
make lint
```

## Stack'i ayağa kaldırma

```sh
make docker-up
```

## Migration'lar

```sh
make migrate-up
make migrate-down
```

## Branch & PR kuralları

`gokturk-deception-mesh` ile aynı: `main` korumalı, PR + CI zorunlu, squash-only,
force-push/branch silme kapalı.
