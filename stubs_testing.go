//go:build test

package main

import "os"

func init() {
	if svc := os.Getenv("OPCLI_TEST_KEYCHAIN_SERVICE"); svc != "" {
		keychainService = svc
	} else {
		keychainService = "opcli-test"
	}
	testDataDir = os.Getenv("OPCLI_TEST_DATA_DIR")
	testSessionKey = os.Getenv("OPCLI_TEST_SESSION_KEY")
	if os.Getenv("OPCLI_TEST_FILE_KEYCHAIN") != "" {
		if testDataDir == "" {
			panic("OPCLI_TEST_FILE_KEYCHAIN needs OPCLI_TEST_DATA_DIR")
		}
		if err := os.MkdirAll(testDataDir, 0700); err != nil {
			panic(err)
		}
		testKeychainDir = testDataDir
	}
}
