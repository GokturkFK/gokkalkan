<div align="center">

# GÖKKALKAN

**Agentic AI Runtime Security — MCP Egress Proxy & Agent Honeypot Deception (Göktürk Platform P2)**

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Storage-4169E1?style=flat-square&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![MITRE ATLAS](https://img.shields.io/badge/Framework-MITRE%20ATLAS-C7252B?style=flat-square)](docs/THREAT_MODEL.md)
[![OWASP](https://img.shields.io/badge/Standard-OWASP%20Agentic%20Top%2010-181717?style=flat-square)](docs/THREAT_MODEL.md)
[![Status](https://img.shields.io/badge/Status-End--to--End%20Working-22c55e?style=flat-square)](PROJECT_PLAN.md)
[![Org](https://img.shields.io/badge/Org-GokturkFK-0d1117?style=flat-square)](https://github.com/GokturkFK)

*Block prompt-injected or tool-poisoned AI agents from reaching unauthorized endpoints at runtime, emit Critical SOC alerts + cryptographically signed action receipts, and let legitimate tool calls pass unobstructed.*

</div>

---

## Demo

![GÖKKALKAN live demo](docs/demo.gif)

*Recorded against a live `docker compose` stack (PostgreSQL + `gokkalkan`) following [`docs/demo-script.md`](docs/demo-script.md). Legitimate calls reach `api.github.com` and return `200 OK`; poisoned/unauthorized calls are intercepted and produce a Critical alert with a signed action receipt.*

---

## Overview

**GÖKKALKAN** is Pillar 2 (P2) of the Göktürk Security Platform, protecting **Model Context Protocol (MCP)** and autonomous AI agent runtimes against tool poisoning, prompt injection, and unauthorized egress.

It imports [`gokturk-core`](https://github.com/GokturkFK/gokturk-core) directly—reusing the exact same `trap.Provider`/`TripEvent` wire contract and zero-FP `correlate.Evaluate` engine as [`gokturk-deception-mesh`](https://github.com/GokturkFK/gokturk-deception-mesh) and [`gokzincir`](https://github.com/GokturkFK/gokzincir).

- Threat model & NSA MCP / OWASP Agentic Top 10 mapping: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- Architectural decisions: [`docs/DECISIONS.md`](docs/DECISIONS.md)
- Project plan: [`PROJECT_PLAN.md`](PROJECT_PLAN.md)

---

## Architecture

```mermaid
flowchart LR
    Agent["AI Agent / MCP Client"] -->|"MCP / HTTP Call"| GW["internal/gateway<br/>Unified Request Pipeline"]

    GW --> Proxy["internal/proxy<br/>Deny-by-Default Allowlist"]
    Proxy -->|"allowlisted"| Target["Legitimate Endpoint<br/>(e.g. api.github.com)"]
    Proxy -->|"unlisted or decoy"| Honeypot["internal/honeypot<br/>Fake MCP Tool Provider + Decoder"]
    GW -->|"scan tool metadata"| Detect["internal/detect<br/>Prompt-Injection & Tool-Poisoning"]

    Honeypot -->|"TripEvent (AML.T0053)"| Core["gokturk-core<br/>correlate.Evaluate"]
    Detect -->|"TripEvent (AML.T0110.000)"| Core

    Core --> Alert["Alert<br/>High / Critical"]
    Alert -->|"Critical"| Enforce["Runtime Enforcement<br/>Revoke Agent Identity"]
    Alert --> Receipt["Signed Action Receipt<br/>Tamper-Evident Audit"]
    Alert --> Panel["Unified SOC Feed<br/>GET /api/v1/alerts"]

    style Honeypot fill:#7f1d1d,color:#fff,stroke:#b91c1c
    style Detect fill:#7f1d1d,color:#fff,stroke:#b91c1c
    style Target fill:#14532d,color:#fff,stroke:#16a34a
```

### Core Packages

| Package | Responsibility | Contract |
| :--- | :--- | :--- |
| **`internal/gateway`** | Single request pipeline unifying proxy, detection, honeypot, correlation, enforcement, and receipts | End-to-end HTTP/MCP gateway |
| **`internal/proxy`** | Deny-by-default egress allowlist enforcement (host, method, path-prefix) | Pure evaluator backed by `Store` interface |
| **`internal/honeypot`** | Decoy MCP tool provisioning and invocation detection (`AML.T0053`) | `gokturk-core/trap.Provider`, `trap.Decoder` |
| **`internal/detect`** | Tool-description scanning for prompt injection & tool poisoning (`AML.T0110.000`) | `gokturk-core/trap.Decoder` |

---

## Getting Started

### Prerequisites

- **Go 1.25+**
- **Docker** & **Docker Compose v2+**

### Run the Stack

```sh
cp deployments/docker/.env.example deployments/docker/.env
make docker-up
```

### Development, Testing & Migrations

```sh
make build
make test
make lint

# Database migrations
make migrate-up
make migrate-down
```

### Branch & PR Rules

Same as `gokturk-deception-mesh`: `main` is protected, PR + CI required, squash-only merges, force-push and branch deletion disabled. Work is tracked as [issues](../../issues) — `cyber` = [@fetihcakmak](https://github.com/fetihcakmak) (security core), `devops` = [@uzunkubra50](https://github.com/uzunkubra50) (platform/delivery/wiring). File ownership: [`CODEOWNERS`](CODEOWNERS).

---

## Göktürk Security Platform

| Pillar | Repository | Focus |
| :---: | :--- | :--- |
| **Core** | [**`gokturk-core`**](https://github.com/GokturkFK/gokturk-core) | Frozen `trap` wire contract & deterministic `correlate` engine |
| **P1** | [**`gokturk-deception-mesh`**](https://github.com/GokturkFK/gokturk-deception-mesh) | Credential canaries, SSH sensor, NATS JetStream & unified SOC dashboard |
| **P2** | **`gokkalkan`** *(this repo)* | Agentic AI runtime security — MCP egress proxy & agent honeypot |
| **P3** | [**`gokzincir`**](https://github.com/GokturkFK/gokzincir) | Non-Human Identity (NHI) governance & blast-radius graph |

---

<div align="center">
  <sub>Developed by <a href="https://github.com/GokturkFK">GokturkFK</a> · Security Kernel: <a href="https://github.com/fetihcakmak">@fetihcakmak</a> · Platform/DevOps: <a href="https://github.com/uzunkubra50">@uzunkubra50</a></sub>
</div>
