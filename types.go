package main

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

// Keyset represents a keyset from account_objects
type Keyset struct {
	KeysetUUID   string `json:"keyset_uuid"`
	SN           int    `json:"sn"`
	PubKey       string `json:"pub_key"`       // JSON-encoded RSA public key
	EncPriKey    string `json:"enc_pri_key"`   // JSON-encoded EncryptedData
	EncSymKey    string `json:"enc_sym_key"`   // JSON-encoded EncryptedData
	EncSignKey   string `json:"enc_sign_key"`
	PubSignKey   string `json:"pub_sign_key"`
	EncryptedBy  string `json:"encrypted_by"` // "mp" for master password, or keyset UUID
}

// Vault represents a vault from account_objects
type Vault struct {
	VaultUUID    string `json:"vault_uuid"`
	VaultType    string `json:"vault_type"`
	EncVaultKey  string `json:"enc_vault_key"`  // JSON-encoded EncryptedData
	EncAttrs     string `json:"enc_attrs"`      // JSON-encoded EncryptedData
}

// ItemOverview contains the encrypted overview data for an item
type ItemOverview struct {
	ID           int64
	UUID         string
	VaultID      int64
	TemplateUUID string
	EncOverview  EncryptedData
}

// ItemDetail contains the encrypted detail data for an item
type ItemDetail struct {
	ID         int64
	EncDetails EncryptedData
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

// DecryptedItem is the decrypted item details
type DecryptedItem struct {
	ItemUUID string  `json:"itemUUID"`
	Fields   []Field `json:"fields,omitempty"`
	Sections []Section `json:"sections,omitempty"`
}

type Field struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Type        string `json:"type,omitempty"`
	Value       string `json:"value,omitempty"`
	Designation string `json:"designation,omitempty"`
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
