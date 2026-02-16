-- 1Password core_db migration to version 17
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

ALTER TABLE enc_resources
    RENAME TO enc_resources_old;
CREATE TABLE resources (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          BLOB    NOT NULL,
    data          BLOB    NOT NULL,
    k_bucket      INTEGER NULL,
    account_id    INTEGER NULL,
    cache_control INTEGER NULL,
    is_encrypted  INTEGER NOT NULL,
    CHECK ( (is_encrypted = 0 OR is_encrypted = 1) AND (is_encrypted = 0 OR
                                                        (account_id IS NOT NULL AND k_bucket IS NOT NULL)) ),
    UNIQUE (account_id, name) ON CONFLICT REPLACE,
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
);
insert into resources (name, data, k_bucket, account_id, cache_control, is_encrypted)
SELECT enc_name, data, k_bucket, account_id, cache_control, 1
from enc_resources_old;
drop table enc_resources_old;
CREATE INDEX IF NOT EXISTS idx_resources_k_bucket_account_id ON resources (k_bucket, account_id);
UPDATE config
SET value=17
WHERE name = 'version';
