package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// base64URLDecode decodes base64url data, handling missing padding
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// compute2SKD implements the Two-Secret Key Derivation process
// Returns the derived key (either MUK or SRP-X depending on algorithm)
func compute2SKD(secretKey, password, email string, salt []byte, iterations int, algorithm string) ([]byte, error) {
	// Parse secret key: A3-XXXXX-YYYYY-ZZZZZ-...
	// Format: version (2 chars) - accountID (next 6 chars after dash) - secret (rest without dashes)
	parts := strings.Split(secretKey, "-")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid secret key format")
	}

	version := parts[0]  // e.g. "A3"
	accountID := parts[1] // first 6-char segment
	// Secret is all the remaining parts joined without dashes
	secret := strings.Join(parts[2:], "")

	// Normalize email to lowercase
	emailLower := strings.ToLower(email)

	// Step 1: HKDF to stretch salt with email
	// HKDF(ikm=salt, len=32, salt=email, hash=SHA256, count=1, info=algorithm)
	hkdfReader := hkdf.New(sha256.New, salt, []byte(emailLower), []byte(algorithm))
	hkdfPassSalt := make([]byte, 32)
	if _, err := hkdfReader.Read(hkdfPassSalt); err != nil {
		return nil, fmt.Errorf("HKDF for password salt failed: %w", err)
	}

	// Step 2: PBKDF2 with the password
	// PBKDF2(sha256, password, salt=HKDF_salt, iterations=p2c, 32 bytes)
	passwordKey := pbkdf2.Key([]byte(password), hkdfPassSalt, iterations, 32, sha256.New)

	// Step 3: HKDF on the secret key
	// HKDF(ikm=secret, len=32, salt=accountID, hash=SHA256, count=1, info=version)
	hkdfReader = hkdf.New(sha256.New, []byte(secret), []byte(accountID), []byte(version))
	secretKeyDerived := make([]byte, 32)
	if _, err := hkdfReader.Read(secretKeyDerived); err != nil {
		return nil, fmt.Errorf("HKDF for secret key failed: %w", err)
	}

	// Step 4: XOR the results to get the final key
	finalKey := make([]byte, 32)
	for i := 0; i < 32; i++ {
		finalKey[i] = passwordKey[i] ^ secretKeyDerived[i]
	}

	return finalKey, nil
}

// decryptAESGCM decrypts data using AES-256-GCM
func decryptAESGCM(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// The ciphertext includes the GCM tag at the end (last 16 bytes)
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("GCM decryption failed: %w", err)
	}

	return plaintext, nil
}

// decryptEncryptedData decrypts an EncryptedData structure using the provided key
func decryptEncryptedData(ed *EncryptedData, key []byte) ([]byte, error) {
	if ed.Enc != "A256GCM" {
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", ed.Enc)
	}

	iv, err := base64URLDecode(ed.IV)
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	ciphertext, err := base64URLDecode(ed.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	return decryptAESGCM(ciphertext, key, iv)
}

// decryptPBES2 decrypts an EncryptedData structure that uses PBES2 (password-based encryption)
func decryptPBES2(ed *EncryptedData, secretKey, password, email string) ([]byte, error) {
	if !strings.HasPrefix(ed.Alg, "PBES2") {
		return nil, fmt.Errorf("not a PBES2 encrypted structure: %s", ed.Alg)
	}

	salt, err := base64URLDecode(ed.P2s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PBES2 salt: %w", err)
	}

	// Derive the key using 2SKD
	key, err := compute2SKD(secretKey, password, email, salt, ed.P2c, ed.Alg)
	if err != nil {
		return nil, fmt.Errorf("2SKD key derivation failed: %w", err)
	}

	return decryptEncryptedData(ed, key)
}

// extractSymmetricKey extracts the symmetric key bytes from decrypted JWK JSON
func extractSymmetricKey(jwkJSON []byte) ([]byte, error) {
	var jwk JWK
	if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}

	if jwk.Kty != "oct" {
		return nil, fmt.Errorf("expected symmetric key (oct), got %s", jwk.Kty)
	}

	return base64URLDecode(jwk.K)
}
