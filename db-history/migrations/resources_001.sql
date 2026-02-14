-- 1Password resources_db migration to version 1
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/resources_db/db.rs

CREATE TABLE resources (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          BLOB    NOT NULL,
    data          BLOB    NOT NULL,
    k_bucket      INTEGER NULL,
    account_uuid  INTEGER NULL,
    cache_control INTEGER NULL,
    is_encrypted  INTEGER NOT NULL,
    CHECK ( (is_encrypted = 0 OR is_encrypted = 1) AND (is_encrypted = 0 OR
                                                        (account_uuid IS NOT NULL AND k_bucket IS NOT NULL)) ),
    UNIQUE (account_uuid, name) ON CONFLICT REPLACE
);

CREATE INDEX idx_resources_k_bucket_account_uuid ON resources (k_bucket, account_uuid);

CREATE UNIQUE INDEX idx_resources_name_account_uuid_is_encrypted ON resources (
    name, coalesce(account_uuid, is_encrypted));

CREATE TABLE IF NOT EXISTS config (
    name    TEXT    PRIMARY KEY,
    value   TEXT    NOT NULL
);

INSERT INTO config (name, value) VALUES ("version", 1);
