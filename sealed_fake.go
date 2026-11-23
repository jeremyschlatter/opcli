//go:build test

package main

// Test builds fake the Secure Enclave: its key is a plain AES key, and Touch
// ID always succeeds unless OPCLI_TEST_TOUCHID_FAIL is set. If
// OPCLI_TEST_TOUCHID_LOG names a file, each prompt appends its reason to it as
// a line.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"os"
)

func seCreate() (key, pub []byte, err error) {
	key = make([]byte, 32)
	rand.Read(key)
	return key, key, nil
}

func seGCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return gcm
}

func seWrap(pub, msg []byte) ([]byte, error) {
	gcm := seGCM(pub)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	return gcm.Seal(nonce, nonce, msg, nil), nil
}

func seUnwrap(key, blob []byte, reason string) (msg, pub []byte, err error) {
	if log := os.Getenv("OPCLI_TEST_TOUCHID_LOG"); log != "" {
		f, err := os.OpenFile(log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			panic(err)
		}
		f.WriteString(reason + "\n")
		f.Close()
	}
	if os.Getenv("OPCLI_TEST_TOUCHID_FAIL") != "" {
		return nil, nil, ErrAuthRefused
	}
	gcm := seGCM(key)
	if len(blob) < gcm.NonceSize() {
		return nil, nil, errors.New("sealed credentials are truncated")
	}
	msg, err = gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], nil)
	return msg, key, err
}
