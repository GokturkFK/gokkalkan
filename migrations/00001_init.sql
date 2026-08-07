-- +goose Up
-- trip_events / alerts: gokturk-core'daki trap.TripEvent / correlate.Alert ile
-- birebir hizali (gokturk-deception-mesh/migrations/00001_init.sql ile ayni
-- sekil, sema kaymasi olmasin diye kasitli).
--
-- KASITLI OLARAK YOK: traps (honeypot tool/agent kimlik) tablosu. Bu, GK-B'nin
-- guvenlik tasarimina ait (sahte MCP tool'un neye benzedigi, hangi agent'in
-- neye izinli oldugu) -- DevOps bunu onceden tahmin edip dondurmuyor. O yuzden
-- trip_id burada bir FK degil, duz metin (traps tablosu netlesince ayri bir
-- migration'da FK eklenir).
--
-- Bkz. PROJECT_PLAN.md bol. 3 (sozlesmeler) ve bol. 5 (GKO-6).

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE trip_events (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id      text NOT NULL UNIQUE,
    trap_id       text NOT NULL,
    sensor        text NOT NULL,
    source        text NOT NULL,
    observed_at   timestamptz NOT NULL,
    raw           jsonb NOT NULL DEFAULT '{}'::jsonb,
    alert_id      uuid,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_trip_events_trap_id ON trip_events (trap_id);
CREATE INDEX idx_trip_events_source ON trip_events (source);

CREATE TABLE alerts (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    severity      text NOT NULL CHECK (severity IN ('High', 'Critical')),
    technique     text,
    source        text NOT NULL,
    status        text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'ack', 'closed')),
    first_seen    timestamptz NOT NULL,
    last_seen     timestamptz NOT NULL,
    trip_count    integer NOT NULL DEFAULT 1,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE trip_events
    ADD CONSTRAINT fk_trip_events_alert
    FOREIGN KEY (alert_id) REFERENCES alerts (id);

CREATE INDEX idx_alerts_source ON alerts (source);
CREATE INDEX idx_alerts_status ON alerts (status);

-- +goose Down
ALTER TABLE trip_events DROP CONSTRAINT IF EXISTS fk_trip_events_alert;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS trip_events;
