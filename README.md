# GÖKKALKAN

Agentic AI Runtime Security — MCP/agent egress proxy + agent honeypot deception.
Göktürk platformunun P2'si (bkz. [gokturk-core](https://github.com/GokturkFK/gokturk-core),
[gokturk-deception-mesh](https://github.com/GokturkFK/gokturk-deception-mesh)).
Görev dökümü: [PROJECT_PLAN.md](PROJECT_PLAN.md).

**Tek cümlelik hedef:** Zehirli bir tool açıklamasıyla yetkisiz bir uca
bağlanmaya çalışan bir AI agent, egress proxy tarafından **kesilir**; panelde
Critical alarm + imzalı action receipt üretilir — meşru bir tool çağrısı ise
hiçbir engelle karşılaşmaz.

> Durum: iskelet aşaması (GKO-1/GKO-5 tamamlandı). Proxy'nin
> interception/allowlist/enforcement mantığı (GK-A, GK-B) henüz yazılmadı —
> bkz. PROJECT_PLAN.md ve açık [issue'lar](../../issues).

Sprint 0 tasarım kararları (teknik eşlemesi + şema): [docs/DECISIONS.md](docs/DECISIONS.md).

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
