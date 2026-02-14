-- 1Password core_db migration to version 42
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

-- we are cleaning up left-over objects which should have
-- been deleted by init_040.sql or init_041.sql, but weren't.
DELETE FROM objects
WHERE type = 10; -- object type 10 is ObjectRowType::ActivationHub;
INSERT INTO objects
(key_name, `type`, data, associated_item, associated_account)
SELECT
    -- build the key by concatenating the task name and UUID
    account_id || '-' || name || '-' || uuid,
    -- 10 is ObjectRowType::ActivationHub
    10,
    -- merge the `dirty` column into the JSON data.
    -- Note the `CAST(json AS BLOB)`; without it, the query
    -- will silently convert the column type to `TEXT`,
    -- leading to application errors. Note also that
    -- this is NOT the same as using the `jsonb_` function
    -- variants, those return a custom binary format that really
    -- isn't useful to application code since it's not parseable
    -- by tools like serde, its not text, its a custom binary format.
    -- With `BLOB` we are just storing JSON text as bytes.
    CAST(json_set(
        definition,
        '$.dirty',
        CASE
            WHEN dirty = 0 THEN json('false')
            ELSE json('true')
        END
    ) AS BLOB) AS data,
    -- ActivationHub tasks do not have an associated item
    NULL,
    account_id
FROM activation_hub_tasks
-- there shouldn't be any, but in case there are,
-- ignore rows with corrupted JSON; the 2nd parameter
-- is a bitmask, see: https://sqlite.org/json1.html#the_json_valid_function
WHERE json_valid(definition, 6) = 1;
UPDATE config
SET value = 42
WHERE name = 'version';
