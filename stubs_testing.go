//go:build test

package main

import "os"

func init() {
	keychainService = "opcli-test"
	testSessionKey = os.Getenv("OPCLI_TEST_SESSION_KEY")
}
