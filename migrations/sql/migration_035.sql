-- 1Password core_db migration to version 35
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

CREATE TABLE IF NOT EXISTS snippet_shortcuts (
	account_id INT NOT NULL,
	shortcut TEXT NOT NULL,
	item_id INT NOT NULL,
	PRIMARY KEY(item_id) ON CONFLICT REPLACE
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
	FOREIGN KEY (item_id) REFERENCES item_overviews (id) ON DELETE CASCADE
);
UPDATE config
SET value = 35
WHERE name = 'version';
