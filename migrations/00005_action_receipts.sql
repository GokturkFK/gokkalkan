-- +goose Up
-- GKO-3: imzali action receipt (PROJECT_PLAN.md EPIC GK-D).
-- Her dis cagri denemesi icin denetlenebilir kanit: kim, ne zaman, hangi
-- cagriyi denedi, ne karar verildi ve bu iddianin imzasi.
--
-- Not: imza ANAHTARI burada tutulmaz; sadece hangi anahtarla imzalandigini
-- gosteren key_id (public key'in kisa ozeti) saklanir. Ozel anahtar
-- operator tarafindan ortam degiskeni/secret olarak enjekte edilir.

CREATE TABLE action_receipts (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    text NOT NULL,
    method      text NOT NULL,
    host        text NOT NULL,
    path        text NOT NULL,
    allowed     boolean NOT NULL,
    reason      text NOT NULL DEFAULT '',
    issued_at   timestamptz NOT NULL,
    key_id      text NOT NULL,
    signature   text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Denetim sorgulari: "bu agent ne yapti" ve "su tarihte neler oldu".
CREATE INDEX idx_action_receipts_agent_id ON action_receipts (agent_id);
CREATE INDEX idx_action_receipts_issued_at ON action_receipts (issued_at);

-- agent_id'ye FK KONULMADI: receipt bir DENETIM kaydidir ve kayitli
-- olmayan/silinmis bir agent'in denemesi de kanit degeri tasir. FK,
-- agent silinince kaniti da silerdi.

-- +goose Down
DROP TABLE IF EXISTS action_receipts;
