package migrations

import (
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
		grouped := map[kanonKey][]int{}
		for rows.Next() {
			var itemID, accountID int64
			var hashVal int
			if err := rows.Scan(&itemID, &accountID, &hashVal); err != nil {
				return fmt.Errorf("v55: scan kanon: %w", err)
			}
			k := kanonKey{itemID, accountID}
			grouped[k] = append(grouped[k], hashVal)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("v55: iterate kanon: %w", err)
		}

		for k, hashes := range grouped {
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
		rejectionReason sql.NullString
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
			"rejectionReason": r.rejectionReason.String,
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
