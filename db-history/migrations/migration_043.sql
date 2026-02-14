-- 1Password core_db migration to version 43
-- Extracted from 1Password 8 binary (index.node)
-- Source: data/op-db/src/core_db/db.rs

-- feature flags were in the objects table before, then moved out,
-- since we're moving them back, we're going to reuse the ObjectRowType
-- value, so clean out any existing ones
-- 5 is ObjectRowType::FeatureFlag
-- 19 is ObjectRowType::PreRegistrationFeatureFlag
DELETE FROM objects WHERE `type` = 5;
INSERT INTO objects (key_name, `type`, data, associated_account, associated_item)
SELECT
    -- build the key in the same format as the ObjectConfig impl
    account_id || '-' || name,
    5,
    data,
    account_id,
    NULL
FROM account_feature_flags;
DROP TABLE IF EXISTS account_feature_flags;
INSERT INTO objects (key_name, `type`, data, associated_account, associated_item)
SELECT
    -- build the key in the same format as the ObjectConfig impl
    name,
    19,
    data,
    NULL,
    NULL
FROM pre_registration_feature_flags;
DROP TABLE IF EXISTS pre_registration_feature_flags;
UPDATE config
SET value = 43
WHERE name = 'version';
