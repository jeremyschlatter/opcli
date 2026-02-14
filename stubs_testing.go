//go:build test

package main

import "os"

func init() {
	keychainService = "opcli-test"
	testDataDir = os.Getenv("OPCLI_TEST_DATA_DIR")
	testSessionKey = os.Getenv("OPCLI_TEST_SESSION_KEY")
}
