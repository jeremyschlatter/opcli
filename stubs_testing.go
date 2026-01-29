//go:build test

package main

import "os"

func init() {
	keychainService = "opcli-test"
	testDBPath = os.Getenv("OPCLI_TEST_DB")
	testDataDir = os.Getenv("OPCLI_TEST_DATA_DIR")
	testSessionKey = os.Getenv("OPCLI_TEST_SESSION_KEY")
}
