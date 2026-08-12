-- +goose Up
-- GK-B1 (#4, honeypot provider) merge edildi ve trip_events.trap_id'yi
-- gercekten honeypot_tools.id degeriyle dolduruyor (internal/honeypot,
-- Decoder.Decode). 00002'de ertelenen FK artik guvenle kurulabilir.
--
-- trap_id (00001'de "text") uuid'ye cevrilir; USING cast mevcut satirlarda
-- gecersiz bir uuid varsa migration'i acikca patlatir (sessiz veri kaybi
-- yerine). Bu asamada (proje production'a cikmadi) bos tablo bekleniyor.

ALTER TABLE trip_events
    ALTER COLUMN trap_id TYPE uuid USING trap_id::uuid;

ALTER TABLE trip_events
    ADD CONSTRAINT fk_trip_events_trap
    FOREIGN KEY (trap_id) REFERENCES honeypot_tools (id);

-- +goose Down
ALTER TABLE trip_events DROP CONSTRAINT IF EXISTS fk_trip_events_trap;
ALTER TABLE trip_events ALTER COLUMN trap_id TYPE text USING trap_id::text;
