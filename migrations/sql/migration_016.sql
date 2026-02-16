-- 1Password core_db migration to version 16
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

ALTER TABLE enc_resources
    RENAME TO enc_resources_old;
CREATE TABLE enc_resources (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id    INTEGER NOT NULL,
    enc_name      BLOB    NOT NULL,
    data          BLOB    NOT NULL,
    k_bucket      INTEGER,
    cache_control INTEGER NULL,
    UNIQUE (account_id, enc_name) ON CONFLICT REPLACE,
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
);
INSERT INTO enc_resources (id, account_id, enc_name, data, k_bucket, cache_control)
SELECT id, account_id, enc_name, data, k_bucket, (strftime('%s', 'now') + 1296000)
FROM enc_resources_old;
DROP TABLE enc_resources_old;
UPDATE config
SET value=16
WHERE name = 'version';
