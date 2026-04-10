package main

import (
	"sync"
	"sync/atomic"
	"testing"
)

// tryKeychainAccess checks if the keychain is accessible from this process.
// Returns false if the binary is unsigned or keychain access is restricted.
func tryKeychainAccess() bool {
	testKey := "opcli-access-probe"
	err := keychainSet(testKey, "probe")
	if err != nil {
		return false
	}
	keychainDelete(testKey)
	return true
}

// TestKeychainConcurrentRead verifies that concurrent keychainGet calls
// on an existing item all succeed. This is the baseline — pure reads
// should never fail.
func TestKeychainConcurrentRead(t *testing.T) {
	if !tryKeychainAccess() {
		t.Skip("keychain not accessible (binary may be unsigned)")
	}

	testAccount := "concurrent-read-test"
	testValue := "test-value-for-concurrent-reads"
	if err := keychainSet(testAccount, testValue); err != nil {
		t.Fatalf("setup keychainSet failed: %v", err)
	}
	t.Cleanup(func() { keychainDelete(testAccount) })

	const goroutines = 50
	const iterations = 100

	var failures atomic.Int64
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				val, err := keychainGet(testAccount)
				if err != nil {
					failures.Add(1)
					continue
				}
				if val != testValue {
					t.Errorf("keychainGet returned wrong value: got %q, want %q", val, testValue)
				}
			}
		}()
	}
	wg.Wait()

	if f := failures.Load(); f > 0 {
		t.Errorf("keychainGet failed %d/%d times under concurrent reads (no writes)", f, goroutines*iterations)
	}
}
