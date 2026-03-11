package migrations

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
)

// goMigrations maps version numbers to Go functions for migrations that
// were originally implemented in Rust (not SQL). These were reconstructed
// from binary strings in the 1Password desktop app.
var goMigrations = map[int]func(*sql.DB) error{
	44: migrateV44Policies,
	49: migrateV49SSHPubkeys,
	53: migrateV53Collections,
	55: migrateV55Autofill,
	57: migrateV57Categories,
	58: migrateV58EditingDrafts,
	60: migrateV60Keysets,
	61: migrateV61Tables,
}

func tableExists(db *sql.DB, name string) (bool, error) {
	var n int
	err := db.QueryRow("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&n)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

// migrateV44Policies moves account_policies → objects (type 20).
// Note: targets `objects`, not `objects_associated` (which doesn't exist until v46).
func migrateV44Policies(db *sql.DB) error {
	exists, err := tableExists(db, "account_policies")
	if err != nil {
		return err
	}
	if !exists {
		_, err = db.Exec("UPDATE config SET value = 44 WHERE name = 'version'")
		return err
	}

	// Build account_uuid → row id mapping.
	accountMap := map[string]int64{}
	{
		rows, err := db.Query("SELECT account_uuid, id FROM accounts")
		if err != nil {
			return fmt.Errorf("v44: query accounts: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var uuid string
			var id int64
			if err := rows.Scan(&uuid, &id); err != nil {
				return fmt.Errorf("v44: scan account: %w", err)
			}
			accountMap[uuid] = id
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("v44: iterate accounts: %w", err)
		}
	}

	rows, err := db.Query("SELECT account_uuid, policy_name, definition, definition_hash FROM account_policies")
	if err != nil {
		return fmt.Errorf("v44: query policies: %w", err)
	}
	defer rows.Close()

	type policyRow struct {
		accountUUID    string
		policyName     string
		definition     []byte
		definitionHash []byte
	}
	var policies []policyRow
	for rows.Next() {
		var p policyRow
		if err := rows.Scan(&p.accountUUID, &p.policyName, &p.definition, &p.definitionHash); err != nil {
			return fmt.Errorf("v44: scan policy: %w", err)
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("v44: iterate policies: %w", err)
	}

	for _, p := range policies {
		accountID, ok := accountMap[p.accountUUID]
		if !ok {
			continue
		}
		var policy json.RawMessage
		if err := json.Unmarshal(p.definition, &policy); err != nil {
			return fmt.Errorf("v44: parse policy definition: %w", err)
		}
		data, err := json.Marshal(map[string]any{
			"policy":          policy,
			"definition_hash": fmt.Sprintf("%x", p.definitionHash),
		})
		if err != nil {
			return fmt.Errorf("v44: marshal policy: %w", err)
		}
		keyName := fmt.Sprintf("%d-%s", accountID, p.policyName)
		_, err = db.Exec(
			"INSERT INTO objects (key_name, type, data, associated_account, associated_item) VALUES (?, 20, ?, ?, NULL)",
			keyName, data, accountID,
		)
		if err != nil {
			return fmt.Errorf("v44: insert policy: %w", err)
		}
	}

	if _, err := db.Exec("DROP TABLE IF EXISTS account_policies"); err != nil {
		return fmt.Errorf("v44: drop table: %w", err)
	}
	_, err = db.Exec("UPDATE config SET value = 44 WHERE name = 'version'")
	return err
}

// migrateV49SSHPubkeys moves ssh_pubkeys → objects_associated (type 3).
func migrateV49SSHPubkeys(db *sql.DB) error {
	exists, err := tableExists(db, "ssh_pubkeys")
	if err != nil {
		return err
	}
	if !exists {
		_, err = db.Exec("UPDATE config SET value = 49 WHERE name = 'version'")
		return err
	}

	rows, err := db.Query("SELECT item_id, config_order, pubkey, integrity_hash FROM ssh_pubkeys")
	if err != nil {
		return fmt.Errorf("v49: query ssh_pubkeys: %w", err)
	}
	defer rows.Close()

	type sshRow struct {
		itemID        int64
		configOrder   int
		pubkey        []byte
		integrityHash []byte
	}
	var sshRows []sshRow
	for rows.Next() {
		var r sshRow
		if err := rows.Scan(&r.itemID, &r.configOrder, &r.pubkey, &r.integrityHash); err != nil {
			return fmt.Errorf("v49: scan ssh_pubkey: %w", err)
		}
		sshRows = append(sshRows, r)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("v49: iterate ssh_pubkeys: %w", err)
	}

	// Clear existing type-3 entries.
	if _, err := db.Exec("DELETE FROM objects_associated WHERE type = 3"); err != nil {
		return fmt.Errorf("v49: clear type 3: %w", err)
	}

	for _, r := range sshRows {
		var accountID int64
		var vaultUUID, itemUUID string
		err := db.QueryRow(`
			SELECT account_objects.account_id, account_objects.uuid, item_overviews.uuid
			FROM item_overviews
			INNER JOIN account_objects ON account_objects.id = item_overviews.vault_id
			WHERE item_overviews.id = ?
		`, r.itemID).Scan(&accountID, &vaultUUID, &itemUUID)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return fmt.Errorf("v49: lookup item %d: %w", r.itemID, err)
		}

		data, _ := json.Marshal(map[string]any{
			"pubkey":        base64.StdEncoding.EncodeToString(r.pubkey),
			"configOrder":   r.configOrder,
			"integrityHash": base64.StdEncoding.EncodeToString(r.integrityHash),
		})
		_, err = db.Exec(
			"INSERT INTO objects_associated(key_name, type, associated_item, associated_account, data) VALUES(?, 3, ?, ?, ?)",
			vaultUUID+"."+itemUUID, r.itemID, accountID, data,
		)
		if err != nil {
			return fmt.Errorf("v49: insert ssh pubkey: %w", err)
		}
	}

	if _, err := db.Exec("DROP TABLE IF EXISTS ssh_pubkeys"); err != nil {
		return fmt.Errorf("v49: drop table: %w", err)
	}
	_, err = db.Exec("UPDATE config SET value = 49 WHERE name = 'version'")
	return err
}

// migrateV53Collections moves collection_map → objects_associated (type 28).
func migrateV53Collections(db *sql.DB) error {
	exists, err := tableExists(db, "collection_map")
	if err != nil {
		return err
	}
	if !exists {
		_, err = db.Exec("UPDATE config SET value = 53 WHERE name = 'version'")
		return err
	}

	rows, err := db.Query("SELECT account_id, collection_uuid, vault_ids FROM collection_map")
	if err != nil {
		return fmt.Errorf("v53: query collection_map: %w", err)
	}
	defer rows.Close()

	type collRow struct {
		accountID      int64
		collectionUUID string
		vaultIDs       []byte
	}
	var collRows []collRow
	for rows.Next() {
		var r collRow
		if err := rows.Scan(&r.accountID, &r.collectionUUID, &r.vaultIDs); err != nil {
			return fmt.Errorf("v53: scan collection: %w", err)
		}
		collRows = append(collRows, r)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("v53: iterate collections: %w", err)
	}

	for _, r := range collRows {
		var vaultIDList []int64
		if err := json.Unmarshal(r.vaultIDs, &vaultIDList); err != nil {
			continue
		}

		var vaultUUIDs []string
		for _, vid := range vaultIDList {
			var uuid string
			err := db.QueryRow(
				"SELECT uuid FROM account_objects WHERE id = ? AND object_type = 'vault'", vid,
			).Scan(&uuid)
			if err == sql.ErrNoRows {
				continue
			}
			if err != nil {
				return fmt.Errorf("v53: lookup vault %d: %w", vid, err)
			}
			vaultUUIDs = append(vaultUUIDs, uuid)
		}

		data, _ := json.Marshal(map[string]any{"vaults": vaultUUIDs})
		_, err := db.Exec(
			"INSERT INTO objects_associated(type, key_name, associated_account, data, associated_item) VALUES(28, ?, ?, ?, NULL)",
			r.collectionUUID, r.accountID, data,
		)
		if err != nil {
			return fmt.Errorf("v53: insert collection: %w", err)
		}
	}

	if _, err := db.Exec("DROP TABLE IF EXISTS collection_map"); err != nil {
		return fmt.Errorf("v53: drop table: %w", err)
	}
	_, err = db.Exec("UPDATE config SET value = 53 WHERE name = 'version'")
	return err
}

// migrateV55Autofill moves kanon_autofill → type 31 and autofill → type 32.
func migrateV55Autofill(db *sql.DB) error {
	// kanon_autofill → type 31
	if exists, err := tableExists(db, "kanon_autofill"); err != nil {
		return err
	} else if exists {
		rows, err := db.Query("SELECT item_id, account_id, data FROM kanon_autofill")
		if err != nil {
			return fmt.Errorf("v55: query kanon_autofill: %w", err)
		}
		defer rows.Close()

		type kanonKey struct {
			itemID    int64
			accountID int64
		}
		grouped := map[kanonKey]map[int]bool{}
		for rows.Next() {
			var itemID, accountID int64
			var hashVal int
			if err := rows.Scan(&itemID, &accountID, &hashVal); err != nil {
				return fmt.Errorf("v55: scan kanon: %w", err)
			}
			k := kanonKey{itemID, accountID}
			if grouped[k] == nil {
				grouped[k] = map[int]bool{}
			}
			grouped[k][hashVal] = true
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("v55: iterate kanon: %w", err)
		}

		for k, hashSet := range grouped {
			var vaultUUID, itemUUID string
			err := db.QueryRow(`
				SELECT account_objects.uuid, item_overviews.uuid
				FROM item_overviews
				INNER JOIN account_objects ON account_objects.id = item_overviews.vault_id
				WHERE item_overviews.id = ? AND account_objects.account_id = ?
			`, k.itemID, k.accountID).Scan(&vaultUUID, &itemUUID)
			if err == sql.ErrNoRows {
				continue
			}
			if err != nil {
				return fmt.Errorf("v55: lookup kanon item %d: %w", k.itemID, err)
			}
			hashes := make([]int, 0, len(hashSet))
			for h := range hashSet {
				hashes = append(hashes, h)
			}
			sort.Ints(hashes)
			data, _ := json.Marshal(hashes)
			_, err = db.Exec(
				"INSERT INTO objects_associated(type, key_name, associated_account, associated_item, data) VALUES(31, ?, ?, ?, ?)",
				vaultUUID+"."+itemUUID, k.accountID, k.itemID, data,
			)
			if err != nil {
				return fmt.Errorf("v55: insert kanon: %w", err)
			}
		}
	}

	// autofill → type 32
	if exists, err := tableExists(db, "autofill"); err != nil {
		return err
	} else if exists {
		rows, err := db.Query("SELECT account_id, vault_id, item_id, category, autofill_data FROM autofill")
		if err != nil {
			return fmt.Errorf("v55: query autofill: %w", err)
		}
		defer rows.Close()

		type afRow struct {
			accountID    int64
			vaultID      int64
			itemID       int64
			category     string
			autofillData []byte
		}
		var afRows []afRow
		for rows.Next() {
			var r afRow
			if err := rows.Scan(&r.accountID, &r.vaultID, &r.itemID, &r.category, &r.autofillData); err != nil {
				return fmt.Errorf("v55: scan autofill: %w", err)
			}
			afRows = append(afRows, r)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("v55: iterate autofill: %w", err)
		}

		for _, r := range afRows {
			var vaultUUID, itemUUID string
			err := db.QueryRow(`
				SELECT account_objects.uuid, item_overviews.uuid
				FROM item_overviews
				INNER JOIN account_objects ON account_objects.id = item_overviews.vault_id
				WHERE item_overviews.id = ?
				  AND item_overviews.vault_id = ?
				  AND account_objects.account_id = ?
			`, r.itemID, r.vaultID, r.accountID).Scan(&vaultUUID, &itemUUID)
			if err == sql.ErrNoRows {
				continue
			}
			if err != nil {
				return fmt.Errorf("v55: lookup autofill item %d: %w", r.itemID, err)
			}
			_, err = db.Exec(
				"INSERT INTO objects_associated(type, key_name, associated_account, associated_item, data) VALUES(32, ?, ?, ?, ?)",
				vaultUUID+"."+itemUUID, r.accountID, r.itemID, r.autofillData,
			)
			if err != nil {
				return fmt.Errorf("v55: insert autofill: %w", err)
			}
		}
	}

	if _, err := db.Exec("DROP TABLE IF EXISTS autofill"); err != nil {
		return fmt.Errorf("v55: drop autofill: %w", err)
	}
	if _, err := db.Exec("DROP TABLE IF EXISTS kanon_autofill"); err != nil {
		return fmt.Errorf("v55: drop kanon_autofill: %w", err)
	}
	_, err := db.Exec("UPDATE config SET value = 55 WHERE name = 'version'")
	return err
}

// migrateV57Categories moves account_objects categories → objects_associated (type 33).
func migrateV57Categories(db *sql.DB) error {
	rows, err := db.Query("SELECT account_id, uuid, data FROM account_objects WHERE object_type = 'category'")
	if err != nil {
		return fmt.Errorf("v57: query categories: %w", err)
	}
	defer rows.Close()

	fieldMap := map[string]string{
		"category_uuid": "categoryUuid",
		"changer_uuid":  "changerUuid",
		"is_favorite":   "isFavorite",
	}

	type catRow struct {
		accountID int64
		uuid      string
		data      []byte
	}
	var catRows []catRow
	for rows.Next() {
		var r catRow
		if err := rows.Scan(&r.accountID, &r.uuid, &r.data); err != nil {
			return fmt.Errorf("v57: scan category: %w", err)
		}
		catRows = append(catRows, r)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("v57: iterate categories: %w", err)
	}

	for _, r := range catRows {
		var old map[string]json.RawMessage
		if err := json.Unmarshal(r.data, &old); err != nil {
			return fmt.Errorf("v57: parse category: %w", err)
		}
		newData := map[string]json.RawMessage{}
		for oldKey, val := range old {
			if newKey, ok := fieldMap[oldKey]; ok {
				newData[newKey] = val
			} else {
				newData[oldKey] = val
			}
		}
		data, err := json.Marshal(newData)
		if err != nil {
			return fmt.Errorf("v57: marshal category: %w", err)
		}
		_, err = db.Exec(
			"INSERT INTO objects_associated(type, key_name, associated_account, data, associated_item) VALUES(33, ?, ?, ?, NULL)",
			r.uuid, r.accountID, data,
		)
		if err != nil {
			return fmt.Errorf("v57: insert category: %w", err)
		}
	}

	if _, err := db.Exec("DELETE FROM account_objects WHERE object_type = 'category'"); err != nil {
		return fmt.Errorf("v57: delete categories: %w", err)
	}
	_, err = db.Exec("UPDATE config SET value = 57 WHERE name = 'version'")
	return err
}

// migrateV58EditingDrafts moves editing_drafts → objects_associated (type 30).
func migrateV58EditingDrafts(db *sql.DB) error {
	exists, err := tableExists(db, "editing_drafts")
	if err != nil {
		return err
	}
	if !exists {
		_, err = db.Exec("UPDATE config SET value = 58 WHERE name = 'version'")
		return err
	}

	rows, err := db.Query(`
		SELECT
		  editing_drafts.account_id,
		  editing_drafts.item_id,
		  editing_drafts.vault_id,
		  editing_drafts.rejection_reason,
		  editing_drafts.local_edit_count,
		  editing_drafts.template_uuid,
		  editing_drafts.changer_uuid,
		  editing_drafts.created_at,
		  editing_drafts.enc_details,
		  editing_drafts.favorite,
		  editing_drafts.enc_overview,
		  editing_drafts.trashed,
		  editing_drafts.updated_at,
		  editing_drafts.version,
		  editing_drafts.context,
		  account_objects.uuid || '.' || item_overviews.uuid
		FROM editing_drafts
		INNER JOIN item_overviews ON item_overviews.id = editing_drafts.item_id
		INNER JOIN account_objects ON account_objects.id = item_overviews.vault_id
	`)
	if err != nil {
		return fmt.Errorf("v58: query editing_drafts: %w", err)
	}
	defer rows.Close()

	type draftRow struct {
		accountID       int64
		itemID          int64
		vaultID         int64
		rejectionReason *string
		localEditCount  int
		templateUUID    string
		changerUUID     string
		createdAt       int64
		encDetails      []byte
		favorite        int
		encOverview     []byte
		trashed         int
		updatedAt       int64
		version         int
		context         []byte
		keyName         string
	}
	var draftRows []draftRow
	for rows.Next() {
		var r draftRow
		if err := rows.Scan(
			&r.accountID, &r.itemID, &r.vaultID, &r.rejectionReason,
			&r.localEditCount, &r.templateUUID, &r.changerUUID, &r.createdAt,
			&r.encDetails, &r.favorite, &r.encOverview, &r.trashed,
			&r.updatedAt, &r.version, &r.context, &r.keyName,
		); err != nil {
			return fmt.Errorf("v58: scan draft: %w", err)
		}
		draftRows = append(draftRows, r)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("v58: iterate drafts: %w", err)
	}

	for _, r := range draftRows {
		state := "active"
		if r.trashed != 0 {
			state = "trashed"
		}
		data, _ := json.Marshal(map[string]any{
			"itemId":          r.itemID,
			"categoryUuid":    r.templateUUID,
			"changerUuid":     r.changerUUID,
			"createdAt":       r.createdAt,
			"updatedAt":       r.updatedAt,
			"isFavorite":      r.favorite != 0,
			"state":           state,
			"version":         r.version,
			"rejectionReason": r.rejectionReason,
			"localEditCount":  r.localEditCount,
			"encOverview":     base64.StdEncoding.EncodeToString(r.encOverview),
			"encDetails":      base64.StdEncoding.EncodeToString(r.encDetails),
			"context":         base64.StdEncoding.EncodeToString(r.context),
		})
		_, err := db.Exec(
			"INSERT INTO objects_associated(type, key_name, associated_account, associated_item, data) VALUES(30, ?, ?, ?, ?)",
			r.keyName, r.accountID, r.itemID, data,
		)
		if err != nil {
			return fmt.Errorf("v58: insert draft: %w", err)
		}
	}

	if _, err := db.Exec("DROP TABLE IF EXISTS editing_drafts"); err != nil {
		return fmt.Errorf("v58: drop table: %w", err)
	}
	_, err = db.Exec("UPDATE config SET value = 58 WHERE name = 'version'")
	return err
}

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

// migrateV61Tables restructures the database from integer-ID-based tables to UUID-based tables.
// accounts: integer PK → account_uuid TEXT PK
// account_objects → vaults: dedicated table, enc_vault_key/enc_attrs un-stringified
// item_overviews + item_details → items: merged, data blob includes overview+details
// objects_associated: integer refs → UUID refs
func migrateV61Tables(db *sql.DB) error {
	// Build account id → uuid mapping.
	accountUUIDs := map[int64]string{}
	{
		rows, err := db.Query("SELECT id, account_uuid FROM accounts")
		if err != nil {
			return fmt.Errorf("v61: query accounts: %w", err)
		}
		for rows.Next() {
			var id int64
			var uuid string
			if err := rows.Scan(&id, &uuid); err != nil {
				rows.Close()
				return fmt.Errorf("v61: scan account: %w", err)
			}
			accountUUIDs[id] = uuid
		}
		rows.Close()
	}

	// Build vault id → (account_uuid, vault_uuid) mapping.
	type vaultRef struct {
		accountUUID string
		vaultUUID   string
	}
	vaultRefs := map[int64]vaultRef{}
	{
		rows, err := db.Query("SELECT id, account_id, json_extract(data, '$.vault_uuid') FROM account_objects WHERE object_type = 'vault'")
		if err != nil {
			return fmt.Errorf("v61: query vaults: %w", err)
		}
		for rows.Next() {
			var id, accountID int64
			var vaultUUID string
			if err := rows.Scan(&id, &accountID, &vaultUUID); err != nil {
				rows.Close()
				return fmt.Errorf("v61: scan vault ref: %w", err)
			}
			vaultRefs[id] = vaultRef{accountUUIDs[accountID], vaultUUID}
		}
		rows.Close()
	}

	// Build item id → (account_uuid, vault_uuid, item_uuid) mapping.
	type itemRef struct {
		accountUUID string
		vaultUUID   string
		itemUUID    string
	}
	itemRefs := map[int64]itemRef{}
	{
		rows, err := db.Query("SELECT id, uuid, vault_id FROM item_overviews")
		if err != nil {
			return fmt.Errorf("v61: query item refs: %w", err)
		}
		for rows.Next() {
			var id int64
			var uuid string
			var vaultID int64
			if err := rows.Scan(&id, &uuid, &vaultID); err != nil {
				rows.Close()
				return fmt.Errorf("v61: scan item ref: %w", err)
			}
			vr := vaultRefs[vaultID]
			itemRefs[id] = itemRef{vr.accountUUID, vr.vaultUUID, uuid}
		}
		rows.Close()
	}

	// --- Create new tables ---

	if _, err := db.Exec(`CREATE TABLE accounts_v61 (
		account_uuid TEXT PRIMARY KEY NOT NULL,
		data BLOB NOT NULL
	)`); err != nil {
		return fmt.Errorf("v61: create accounts_v61: %w", err)
	}

	if _, err := db.Exec(`CREATE TABLE vaults (
		account_uuid TEXT NOT NULL,
		vault_uuid TEXT NOT NULL,
		data BLOB NOT NULL,
		PRIMARY KEY (account_uuid, vault_uuid),
		FOREIGN KEY (account_uuid) REFERENCES accounts_v61(account_uuid) ON DELETE CASCADE
	)`); err != nil {
		return fmt.Errorf("v61: create vaults: %w", err)
	}

	if _, err := db.Exec(`CREATE TABLE items (
		account_uuid TEXT NOT NULL,
		vault_uuid TEXT NOT NULL,
		item_uuid TEXT NOT NULL,
		local_edit_count INTEGER NOT NULL,
		rejection_reason INTEGER NOT NULL,
		version INTEGER NOT NULL,
		data BLOB NOT NULL,
		PRIMARY KEY (account_uuid, vault_uuid, item_uuid),
		FOREIGN KEY (account_uuid, vault_uuid) REFERENCES vaults(account_uuid, vault_uuid) ON DELETE CASCADE
	)`); err != nil {
		return fmt.Errorf("v61: create items: %w", err)
	}

	if _, err := db.Exec(`CREATE TABLE objects_associated_v61 (
		type INT NOT NULL,
		account_uuid TEXT NOT NULL,
		key_name TEXT NOT NULL,
		data BLOB NOT NULL,
		vault_uuid TEXT,
		item_uuid TEXT,
		PRIMARY KEY (type, account_uuid, key_name),
		CHECK (
			(vault_uuid IS NULL AND item_uuid IS NULL)
			OR
			(vault_uuid IS NOT NULL AND item_uuid IS NOT NULL)
		),
		FOREIGN KEY (account_uuid) REFERENCES accounts_v61(account_uuid) ON DELETE CASCADE
	)`); err != nil {
		return fmt.Errorf("v61: create objects_associated_v61: %w", err)
	}

	// --- Migrate accounts ---
	if _, err := db.Exec("INSERT INTO accounts_v61 (account_uuid, data) SELECT account_uuid, data FROM accounts"); err != nil {
		return fmt.Errorf("v61: migrate accounts: %w", err)
	}

	// --- Migrate vaults ---
	{
		rows, err := db.Query("SELECT account_id, data FROM account_objects WHERE object_type = 'vault'")
		if err != nil {
			return fmt.Errorf("v61: query vault data: %w", err)
		}
		var vaultRows []struct {
			accountID int64
			data      []byte
		}
		for rows.Next() {
			var accountID int64
			var data []byte
			if err := rows.Scan(&accountID, &data); err != nil {
				rows.Close()
				return fmt.Errorf("v61: scan vault: %w", err)
			}
			vaultRows = append(vaultRows, struct {
				accountID int64
				data      []byte
			}{accountID, data})
		}
		rows.Close()

		for _, vr := range vaultRows {
			accountUUID := accountUUIDs[vr.accountID]

			// Transform vault data: remove vault_uuid, un-stringify enc_vault_key and enc_attrs
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(vr.data, &raw); err != nil {
				return fmt.Errorf("v61: parse vault data: %w", err)
			}

			var vaultUUID string
			json.Unmarshal(raw["vault_uuid"], &vaultUUID)
			delete(raw, "vault_uuid")

			// Un-stringify enc_vault_key and enc_attrs (JSON string → embedded object)
			for _, field := range []string{"enc_vault_key", "enc_attrs"} {
				if val, ok := raw[field]; ok {
					var jsonStr string
					if json.Unmarshal(val, &jsonStr) == nil {
						// It's a JSON string containing JSON — unwrap it
						raw[field] = json.RawMessage(jsonStr)
					}
				}
			}

			newData, err := json.Marshal(raw)
			if err != nil {
				return fmt.Errorf("v61: marshal vault data: %w", err)
			}

			if _, err := db.Exec("INSERT INTO vaults (account_uuid, vault_uuid, data) VALUES (?, ?, ?)",
				accountUUID, vaultUUID, newData); err != nil {
				return fmt.Errorf("v61: insert vault: %w", err)
			}
		}
	}

	// --- Migrate items ---
	{
		rows, err := db.Query(`
			SELECT o.vault_id, o.uuid, o.created_at, o.updated_at, o.template_uuid,
			       o.changer_uuid, o.favorite, o.trashed, o.version,
			       o.local_edit_count, o.rejection_reason, o.enc_overview, o.validated,
			       d.enc_details
			FROM item_overviews o
			INNER JOIN item_details d ON d.id = o.id
		`)
		if err != nil {
			return fmt.Errorf("v61: query items: %w", err)
		}

		type itemRow struct {
			vaultID         int64
			uuid            string
			createdAt       int64
			updatedAt       int64
			templateUUID    string
			changerUUID     string
			favorite        int
			trashed         int
			version         int
			localEditCount  int
			rejectionReason int
			encOverview     []byte
			validated       int
			encDetails      []byte
		}
		var itemRows []itemRow
		for rows.Next() {
			var r itemRow
			if err := rows.Scan(&r.vaultID, &r.uuid, &r.createdAt, &r.updatedAt,
				&r.templateUUID, &r.changerUUID, &r.favorite, &r.trashed,
				&r.version, &r.localEditCount, &r.rejectionReason,
				&r.encOverview, &r.validated, &r.encDetails); err != nil {
				rows.Close()
				return fmt.Errorf("v61: scan item: %w", err)
			}
			itemRows = append(itemRows, r)
		}
		rows.Close()

		for _, r := range itemRows {
			vr := vaultRefs[r.vaultID]

			// Parse enc_overview and enc_details as JSON objects
			var overview, details json.RawMessage
			if err := json.Unmarshal(r.encOverview, &overview); err != nil {
				return fmt.Errorf("v61: parse enc_overview: %w", err)
			}
			if err := json.Unmarshal(r.encDetails, &details); err != nil {
				return fmt.Errorf("v61: parse enc_details: %w", err)
			}

			state := 0
			if r.trashed != 0 {
				state = 1
			}

			data, _ := json.Marshal(map[string]any{
				"category_uuid": r.templateUUID,
				"changer_uuid":  r.changerUUID,
				"created_at":    r.createdAt,
				"updated_at":    r.updatedAt,
				"overview":      overview,
				"details":       details,
				"is_favorite":   r.favorite != 0,
				"state":         state,
				"validated":     r.validated != 0,
			})

			if _, err := db.Exec(
				"INSERT INTO items (account_uuid, vault_uuid, item_uuid, local_edit_count, rejection_reason, version, data) VALUES (?, ?, ?, ?, ?, ?, ?)",
				vr.accountUUID, vr.vaultUUID, r.uuid, r.localEditCount, r.rejectionReason, r.version, data,
			); err != nil {
				return fmt.Errorf("v61: insert item %s: %w", r.uuid, err)
			}
		}
	}

	// --- Migrate objects_associated ---
	{
		rows, err := db.Query("SELECT key_name, type, data, associated_item, associated_account FROM objects_associated")
		if err != nil {
			return fmt.Errorf("v61: query objects_associated: %w", err)
		}

		type oaRow struct {
			keyName    string
			objType    int
			data       []byte
			assocItem  sql.NullInt64
			assocAcct  int64
		}
		var oaRows []oaRow
		for rows.Next() {
			var r oaRow
			if err := rows.Scan(&r.keyName, &r.objType, &r.data, &r.assocItem, &r.assocAcct); err != nil {
				rows.Close()
				return fmt.Errorf("v61: scan objects_associated: %w", err)
			}
			oaRows = append(oaRows, r)
		}
		rows.Close()

		for _, r := range oaRows {
			accountUUID := accountUUIDs[r.assocAcct]
			var vaultUUID, itemUUID sql.NullString
			if r.assocItem.Valid {
				if ir, ok := itemRefs[r.assocItem.Int64]; ok {
					vaultUUID = sql.NullString{String: ir.vaultUUID, Valid: true}
					itemUUID = sql.NullString{String: ir.itemUUID, Valid: true}
				}
			}

			if _, err := db.Exec(
				"INSERT INTO objects_associated_v61 (type, account_uuid, key_name, data, vault_uuid, item_uuid) VALUES (?, ?, ?, ?, ?, ?)",
				r.objType, accountUUID, r.keyName, r.data, vaultUUID, itemUUID,
			); err != nil {
				return fmt.Errorf("v61: insert objects_associated %s (type %d): %w", r.keyName, r.objType, err)
			}
		}
	}

	// --- Drop old tables, rename new ones ---
	for _, stmt := range []string{
		"DROP TABLE IF EXISTS item_details",
		"DROP TABLE IF EXISTS item_overviews",
		"DROP TABLE IF EXISTS objects_associated",
		"DROP TABLE IF EXISTS account_objects",
		"DROP TABLE IF EXISTS accounts",
		"DELETE FROM sqlite_sequence",
		"ALTER TABLE accounts_v61 RENAME TO accounts",
		"ALTER TABLE objects_associated_v61 RENAME TO objects_associated",
		"CREATE INDEX items_rejection_reason ON items(rejection_reason) WHERE rejection_reason <> 0",
		"CREATE INDEX items_local_edit_count ON items(local_edit_count) WHERE local_edit_count <> 0",
		"CREATE INDEX items_version ON items(version) WHERE local_edit_count <> 0",
		"UPDATE config SET value = '61' WHERE name = 'version'",
	} {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("v61: %s: %w", truncate(stmt, 40), err)
		}
	}

	return nil
}
