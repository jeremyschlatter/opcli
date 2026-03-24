package main

import "encoding/json"

// EncryptedData represents the b5+jwk+json encrypted data format used by 1Password
type EncryptedData struct {
	Cty  string `json:"cty"`  // content type, e.g. "b5+jwk+json"
	Kid  string `json:"kid"`  // key ID
	Enc  string `json:"enc"`  // encryption algorithm, e.g. "A256GCM"
	IV   string `json:"iv"`   // base64url-encoded IV
	Data string `json:"data"` // base64url-encoded ciphertext+tag

	// PBES2 parameters (only present for password-encrypted keys)
	Alg string `json:"alg,omitempty"` // e.g. "PBES2g-HS256"
	P2c int    `json:"p2c,omitempty"` // iteration count
	P2s string `json:"p2s,omitempty"` // base64url-encoded salt
}

// Account represents the account data from the accounts table
type Account struct {
	AccountUUID   string         `json:"account_uuid"`
	UserEmail     string         `json:"user_email"`
	UserName      string         `json:"user_name"`
	SignInURL     string         `json:"sign_in_url"`
	EncSrpX       EncryptedData  `json:"enc_srp_x"`
	SignInProvider SignInProvider `json:"sign_in_provider"`
}

type SignInProvider struct {
	Type         string        `json:"type"`
	SecretKey    string        `json:"secret_key"`
	EncUnlockKey EncryptedData `json:"enc_unlock_key"`
}

// Keyset represents a keyset from objects_associated (type 36)
type Keyset struct {
	KeysetUUID  string        // populated from key_name column, not from JSON
	SN          int           `json:"sn"`
	EncPriKey   EncryptedData `json:"encPriKey"`
	EncSymKey   EncryptedData `json:"encSymKey"`
	EncryptedBy string        `json:"encryptedBy"` // "mp" for master password, or keyset UUID
}

// Vault represents a vault from the vaults table
type Vault struct {
	VaultUUID   string        // populated from vault_uuid column
	VaultType   string        `json:"vault_type"`
	EncVaultKey EncryptedData `json:"enc_vault_key"`
	EncAttrs    EncryptedData `json:"enc_attrs"`
}

// Item contains both encrypted overview and detail data for an item
type Item struct {
	UUID         string
	VaultUUID    string
	TemplateUUID string        // from data.category_uuid
	EncOverview  EncryptedData // from data.overview
	EncDetails   EncryptedData // from data.details
}

// DecryptedOverview is the decrypted item overview
type DecryptedOverview struct {
	Title    string   `json:"title"`
	URL      string   `json:"url,omitempty"`
	URLs     []URLEntry `json:"urls,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Ainfo    string   `json:"ainfo,omitempty"` // account info hint
}

type URLEntry struct {
	URL   string `json:"u"`
	Label string `json:"l,omitempty"`
}

// DecryptedItem is the decrypted item details.
// Some 1Password item types (e.g. Password) store data as top-level JSON keys
// rather than in the "fields" array. These are captured in Extras.
type DecryptedItem struct {
	ItemUUID string    `json:"itemUUID"`
	Fields   []Field   `json:"fields,omitempty"`
	Sections []Section `json:"sections,omitempty"`
	Extras   map[string]string `json:"-"` // top-level string keys not in fields/sections
}

// knownItemKeys are the JSON keys handled by DecryptedItem's typed fields.
var knownItemKeys = map[string]bool{
	"itemUUID": true, "fields": true, "sections": true,
}

func (d *DecryptedItem) UnmarshalJSON(data []byte) error {
	// First unmarshal the known fields via an alias to avoid recursion.
	type Alias DecryptedItem
	var alias Alias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*d = DecryptedItem(alias)

	// Then capture any extra top-level string values.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for k, v := range raw {
		if knownItemKeys[k] {
			continue
		}
		var s string
		if json.Unmarshal(v, &s) == nil {
			if d.Extras == nil {
				d.Extras = make(map[string]string)
			}
			d.Extras[k] = s
		}
	}
	return nil
}

type Field struct {
	// Standard format (login items, etc.)
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Type        string `json:"type,omitempty"`
	Value       string `json:"value,omitempty"`
	Designation string `json:"designation,omitempty"`

	// Alternate format (section fields)
	T string `json:"t,omitempty"` // title/label
	N string `json:"n,omitempty"` // internal name/id
	K string `json:"k,omitempty"` // kind (string, concealed, etc.)
	V json.RawMessage `json:"v,omitempty"` // value (string, object, etc.)
}

// FieldLabel returns the user-visible label for the field.
func (f *Field) FieldLabel() string {
	if f.T != "" {
		return f.T
	}
	if f.Name != "" {
		return f.Name
	}
	return f.ID
}

// FieldID returns the internal ID for the field.
func (f *Field) FieldID() string {
	if f.N != "" {
		return f.N
	}
	if f.ID != "" {
		return f.ID
	}
	return f.Name
}

// FieldValue returns the value of the field.
func (f *Field) FieldValue() string {
	if len(f.V) > 0 {
		// If it's a JSON string, unquote it. Otherwise return the raw JSON.
		var s string
		if json.Unmarshal(f.V, &s) == nil {
			return s
		}
		return string(f.V)
	}
	return f.Value
}

type Section struct {
	Name   string  `json:"name,omitempty"`
	Title  string  `json:"title,omitempty"`
	Fields []Field `json:"fields,omitempty"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // key type: "oct", "RSA", etc.
	Kid string `json:"kid"` // key ID
	Alg string `json:"alg,omitempty"`

	// Symmetric key
	K string `json:"k,omitempty"` // base64url-encoded key bytes

	// RSA key components
	N string `json:"n,omitempty"` // modulus
	E string `json:"e,omitempty"` // public exponent
	D string `json:"d,omitempty"` // private exponent
	P string `json:"p,omitempty"` // first prime factor
	Q string `json:"q,omitempty"` // second prime factor
	Dp string `json:"dp,omitempty"` // d mod (p-1)
	Dq string `json:"dq,omitempty"` // d mod (q-1)
	Qi string `json:"qi,omitempty"` // q^-1 mod p
}
