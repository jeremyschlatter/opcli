package migrations

import (
	"database/sql"
	"bytes"
	"encoding/json"
	"fmt"
)

// migrateV60Keysets migrates keysets from the pre-v60 format (account_objects, snake_case,
// JSON-string encoded EncryptedData) to the v60 format (objects_associated type 36,
// camelCase, embedded EncryptedData objects).
//
// UUID moves from JSON field "keyset_uuid" to the "key_name" column.
// account_id → associated_account.
func migrateV60Keysets(db *sql.DB) error {
	rows, err := db.Query(`SELECT account_id, uuid, data FROM account_objects WHERE object_type = 'keyset'`)
	if err != nil {
		return fmt.Errorf("query old keysets: %w", err)
	}
	defer rows.Close()

	type oldKeyset struct {
		accountID int64
		uuid      string
		data      []byte
	}
	var keysets []oldKeyset
	for rows.Next() {
		var ks oldKeyset
		if err := rows.Scan(&ks.accountID, &ks.uuid, &ks.data); err != nil {
			return fmt.Errorf("scan old keyset: %w", err)
		}
		keysets = append(keysets, ks)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate old keysets: %w", err)
	}

	// Field name mappings: old (snake_case) → new (camelCase).
	// These fields are JSON-stringified in the old format and embedded objects in the new.
	keysetFieldMap := map[string]string{
		"enc_sym_key":  "encSymKey",
		"enc_pri_key":  "encPriKey",
		"pub_key":      "pubKey",
		"enc_sign_key": "encSignKey",
		"pub_sign_key": "pubSignKey",
	}

	for _, ks := range keysets {
		var old map[string]json.RawMessage
		if err := json.Unmarshal(ks.data, &old); err != nil {
			return fmt.Errorf("parse old keyset %s: %w", ks.uuid, err)
		}

		newData := map[string]json.RawMessage{
			"sn":          old["sn"],
			"encryptedBy": old["encrypted_by"],
		}

		for oldKey, newKey := range keysetFieldMap {
			raw, ok := old[oldKey]
			if !ok || bytes.Equal(raw, []byte("null")) {
				continue
			}
			// The old value is a JSON string containing JSON. Unwrap it.
			var jsonStr string
			if err := json.Unmarshal(raw, &jsonStr); err != nil {
				return fmt.Errorf("parse %s in keyset %s: %w", oldKey, ks.uuid, err)
			}
			newData[newKey] = json.RawMessage(jsonStr)
		}

		newJSON, err := json.Marshal(newData)
		if err != nil {
			return fmt.Errorf("marshal new keyset %s: %w", ks.uuid, err)
		}

		_, err = db.Exec(
			`INSERT INTO objects_associated (key_name, type, data, associated_account) VALUES (?, 36, ?, ?)`,
			ks.uuid, newJSON, ks.accountID,
		)
		if err != nil {
			return fmt.Errorf("insert migrated keyset %s: %w", ks.uuid, err)
		}
	}

	if _, err := db.Exec(`DELETE FROM account_objects WHERE object_type = 'keyset'`); err != nil {
		return fmt.Errorf("delete old keysets: %w", err)
	}

	_, err = db.Exec(`UPDATE config SET value = '60' WHERE name = 'version'`)
	return err
}
