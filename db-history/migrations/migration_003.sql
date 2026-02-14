-- 1Password core_db migration to version 3
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

ALTER TABLE item_overviews RENAME TO o;
ALTER TABLE item_details RENAME TO d;
CREATE TABLE item_overviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id INTEGER NOT NULL,
    uuid TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    template_uuid TEXT NOT NULL,
    changer_uuid TEXT NOT NULL,
    favorite INTEGER NOT NULL,
    trashed INTEGER NOT NULL,
    version INTEGER NOT NULL,
    local_edit_count INTEGER NOT NULL,
    rejection_reason INTEGER NOT NULL,
    enc_overview BLOB NOT NULL,
    UNIQUE (vault_id, uuid),
    FOREIGN KEY (vault_id) REFERENCES account_objects(id) ON DELETE CASCADE
);
CREATE TABLE item_details (
    id INTEGER PRIMARY KEY,
    enc_details BLOB NOT NULL,
    FOREIGN KEY (id) REFERENCES item_overviews(id) ON DELETE CASCADE
);
INSERT INTO item_overviews (id, vault_id, uuid, created_at, updated_at, template_uuid, changer_uuid, favorite, trashed, version, local_edit_count, rejection_reason, enc_overview)
SELECT id, vault_id, uuid, created_at, updated_at, template_uuid, changer_uuid, favorite, trashed, version, local_edit_count, 0, enc_overview FROM o;
INSERT INTO item_details (id, enc_details) SELECT id, enc_details FROM d;
CREATE INDEX item_overviews_rejection_reason ON item_overviews(rejection_reason) WHERE rejection_reason <> 0;
CREATE INDEX item_overviews_local_edit_count ON item_overviews(local_edit_count) WHERE local_edit_count <> 0;
DROP TABLE d;
DROP TABLE o;
UPDATE config SET value=3 WHERE name='version';
INSERT INTO config (name, value) VALUES ('build_date', 0);
