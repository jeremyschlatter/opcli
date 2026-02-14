package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

type migration struct {
	name           string
	needsMigration func(db *sql.DB) (bool, error)
	migrate        func(db *sql.DB) error
}

// migrations is the list of migrations that transform older DB schemas
// into the format the current code expects. They are applied in-memory
// only; the original DB is never modified.
var migrations = []migration{
	{
		name: "keysets: account_objects → objects_associated",
		needsMigration: func(db *sql.DB) (bool, error) {
			var count int
			err := db.QueryRow(`SELECT count(*) FROM account_objects WHERE object_type = 'keyset'`).Scan(&count)
			if err != nil {
				return false, err
			}
			return count > 0, nil
		},
		migrate: migrateKeysetsUp,
	},
}

// Old keyset JSON format (in account_objects):
//
//	{
//	  "keyset_uuid": "...",
//	  "sn": 1,
//	  "encrypted_by": "mp",
//	  "enc_sym_key": "{\"cty\":\"...\",\"enc\":\"...\", ...}",  // JSON string
//	  "enc_pri_key": "{\"cty\":\"...\",\"enc\":\"...\", ...}",  // JSON string
//	  "pub_key": "{\"kty\":\"RSA\", ...}",                       // JSON string
//	  "enc_sign_key": "...",                                      // optional
//	  "pub_sign_key": "..."                                       // optional
//	}
//
// New keyset JSON format (in objects_associated, type=36):
//
//	{
//	  "sn": 1,
//	  "encryptedBy": "mp",
//	  "encSymKey": { ... },   // embedded object
//	  "encPriKey": { ... },   // embedded object
//	  "pubKey": { ... },      // embedded object
//	  "encSignKey": { ... },  // optional, embedded object
//	  "pubSignKey": { ... }   // optional, embedded object
//	}
//
// UUID moves from JSON field "keyset_uuid" to the "key_name" column.
// account_id → associated_account.

func migrateKeysetsUp(db *sql.DB) error {
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

	for _, ks := range keysets {
		var old map[string]json.RawMessage
		if err := json.Unmarshal(ks.data, &old); err != nil {
			return fmt.Errorf("parse old keyset %s: %w", ks.uuid, err)
		}

		newData := make(map[string]json.RawMessage)

		// Copy sn as-is
		newData["sn"] = old["sn"]

		// Rename encrypted_by → encryptedBy
		newData["encryptedBy"] = old["encrypted_by"]

		// Convert JSON-string fields to embedded objects
		for oldKey, newKey := range map[string]string{
			"enc_sym_key":  "encSymKey",
			"enc_pri_key":  "encPriKey",
			"pub_key":      "pubKey",
			"enc_sign_key": "encSignKey",
			"pub_sign_key": "pubSignKey",
		} {
			raw, ok := old[oldKey]
			if !ok {
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

	_, err = db.Exec(`DELETE FROM account_objects WHERE object_type = 'keyset'`)
	if err != nil {
		return fmt.Errorf("delete old keysets: %w", err)
	}

	return nil
}

// migrateKeysetsDown converts new-format keysets back to old format.
// Used to create test databases with the old schema.
func migrateKeysetsDown(db *sql.DB) error {
	rows, err := db.Query(`SELECT key_name, data, associated_account FROM objects_associated WHERE type = 36`)
	if err != nil {
		return fmt.Errorf("query new keysets: %w", err)
	}
	defer rows.Close()

	type newKeyset struct {
		keyName   string
		data      []byte
		accountID int64
	}
	var keysets []newKeyset
	for rows.Next() {
		var ks newKeyset
		if err := rows.Scan(&ks.keyName, &ks.data, &ks.accountID); err != nil {
			return fmt.Errorf("scan new keyset: %w", err)
		}
		keysets = append(keysets, ks)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate new keysets: %w", err)
	}

	for _, ks := range keysets {
		var newData map[string]json.RawMessage
		if err := json.Unmarshal(ks.data, &newData); err != nil {
			return fmt.Errorf("parse new keyset %s: %w", ks.keyName, err)
		}

		oldData := make(map[string]json.RawMessage)

		// keyset_uuid from key_name column
		uuidJSON, _ := json.Marshal(ks.keyName)
		oldData["keyset_uuid"] = json.RawMessage(uuidJSON)

		// Copy sn as-is
		oldData["sn"] = newData["sn"]

		// Rename encryptedBy → encrypted_by
		oldData["encrypted_by"] = newData["encryptedBy"]

		// Convert embedded objects back to JSON strings
		for newKey, oldKey := range map[string]string{
			"encSymKey":  "enc_sym_key",
			"encPriKey":  "enc_pri_key",
			"pubKey":     "pub_key",
			"encSignKey": "enc_sign_key",
			"pubSignKey": "pub_sign_key",
		} {
			raw, ok := newData[newKey]
			if !ok {
				continue
			}
			// Wrap the object as a JSON string
			strJSON, err := json.Marshal(string(raw))
			if err != nil {
				return fmt.Errorf("stringify %s in keyset %s: %w", newKey, ks.keyName, err)
			}
			oldData[oldKey] = json.RawMessage(strJSON)
		}

		oldJSON, err := json.Marshal(oldData)
		if err != nil {
			return fmt.Errorf("marshal old keyset %s: %w", ks.keyName, err)
		}

		_, err = db.Exec(
			`INSERT INTO account_objects (account_id, uuid, object_type, data) VALUES (?, ?, 'keyset', ?)`,
			ks.accountID, ks.keyName, oldJSON,
		)
		if err != nil {
			return fmt.Errorf("insert old keyset %s: %w", ks.keyName, err)
		}
	}

	_, err = db.Exec(`DELETE FROM objects_associated WHERE type = 36`)
	if err != nil {
		return fmt.Errorf("delete new keysets: %w", err)
	}

	return nil
}
