-- +goose Up
-- GKO-2 wiring sirasinda ortaya cikan entegrasyon catismasinin duzeltmesi.
--
-- 00003, trip_events.trap_id'yi "uuid NOT NULL + honeypot_tools(id) FK"
-- yapti. Bu, GK-B1'in (honeypot tool cagrildi) urettigi event icin dogru:
-- ortada gercekten bizim ektigimiz bir tuzak var ve trap_id onun id'si.
--
-- Ama GK-A2 (zehirli tool aciklamasi tespiti) icin ortada BIZIM BIR TUZAGIMIZ
-- YOK -- disaridan gelen, zehirlenmis, mesru gorunumlu bir tool'un tanimi
-- inceleniyor. O tool honeypot_tools'ta bulunmaz, bulunmamalidir da.
-- Sonuc: GK-A2 event'leri hic yazilamiyordu (gercek Postgres'e karsi
-- dogrulandi: `invalid input syntax for type uuid: "helper-tool"`, ve tool adi
-- gecerli bir uuid olsa bile FK ihlali).
--
-- Cozum: trap_id nullable olur. FK korunur (NULL degerler FK'yi ihlal etmez),
-- yani honeypot event'lerinin referans butunlugu aynen surer; tuzak
-- icermeyen tespitler (GK-A2) NULL yazar ve hangi tool oldugu zaten
-- trip_events.raw icinde durur (bkz. internal/detect/decoder.go, matched_pattern
-- ve tam Invocation raw'a serialize ediliyor).

ALTER TABLE trip_events ALTER COLUMN trap_id DROP NOT NULL;

-- +goose Down
-- Geri alirken NULL trap_id'li satirlar NOT NULL kisitini ihlal eder;
-- bunlar tuzak-icermeyen tespitlerdir, geri donuste silinirler.
DELETE FROM trip_events WHERE trap_id IS NULL;
ALTER TABLE trip_events ALTER COLUMN trap_id SET NOT NULL;
