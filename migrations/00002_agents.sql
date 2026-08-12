-- +goose Up
-- Agent kimlik/allowlist/honeypot semasi: docs/DECISIONS.md Karar 2'de
-- onaylandi (issue #1, GK-S0). GK-A1/GK-A2/GK-B1'in guvenlik tasarimina
-- ait; kolon yapisi burada donuk, icerik (honeypot_tools.description'in
-- nasil "inandirici" olacagi, allowlist granuleritesi) Cyber'in alani.

CREATE TABLE agents (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text NOT NULL UNIQUE,
    token_hash   text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz
);

CREATE TABLE agent_allowlist (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id     uuid NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    method       text NOT NULL DEFAULT '*',
    host         text NOT NULL,
    path_prefix  text NOT NULL DEFAULT '/',
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, method, host, path_prefix)
);

CREATE INDEX idx_agent_allowlist_agent_id ON agent_allowlist (agent_id);

CREATE TABLE honeypot_tools (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text NOT NULL UNIQUE,
    description  text NOT NULL,
    input_schema jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by   text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz
);

-- trip_events.trap_id (00001'de "text") ile honeypot_tools.id (uuid) tip
-- uyusmuyor; dogrudan FK kurulamaz. Bu donusum GK-B1'in trap_id'yi gercekten
-- honeypot_tools.id olarak doldurmaya baslamasindan SONRA, ayri bir
-- migration'da yapilacak (mevcut veride uyumsuz/bos deger riski var).
-- Burada sadece agent/allowlist/honeypot semasi eklenir.
-- GK-B1 merge edildikten sonra bkz. 00003_trip_events_trap_fk.sql.

-- +goose Down
DROP TABLE IF EXISTS honeypot_tools;
DROP TABLE IF EXISTS agent_allowlist;
DROP TABLE IF EXISTS agents;
