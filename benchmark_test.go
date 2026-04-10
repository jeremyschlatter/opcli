package main

import (
	"testing"
	"time"
)

// BenchmarkRead measures the wall-clock time of `opcli read op://vault/item/field`,
// the core read path. The binary is pre-built and credentials pre-stored so we
// measure only the CLI invocation cost.
func BenchmarkRead(b *testing.B) {
	env := setupTestEnv(b, false)
	b.Cleanup(func() { env.cleanup(b) })

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, stderr, code := env.runCLI("", "", nil, "read", "op://Private/Test Login/password")
		if code != 0 {
			b.Fatalf("read failed (exit %d): %s", code, stderr)
		}
	}
}

// Regression threshold for the full CLI read path. This covers process startup,
// database open, key derivation (HKDF + PBKDF2), RSA decrypt, vault lookup,
// AES-GCM decryption, and field extraction.
const readRegressionThreshold = 90 * time.Millisecond

// TestBenchmarkRegressions runs the CLI read benchmark 3 times and fails if the
// median exceeds the regression threshold. This runs as part of `go test` (not
// just `go test -bench`) to catch regressions in CI.
func TestBenchmarkRegressions(t *testing.T) {
	env := setupTestEnv(t, false)
	t.Cleanup(func() { env.cleanup(t) })

	const iterations = 3
	durations := make([]time.Duration, iterations)
	for i := 0; i < iterations; i++ {
		start := time.Now()
		_, stderr, code := env.runCLI("", "", nil, "read", "op://Private/Test Login/password")
		durations[i] = time.Since(start)
		if code != 0 {
			t.Fatalf("read iteration %d failed (exit %d): %s", i, code, stderr)
		}
	}

	sortDurations(durations)
	median := durations[iterations/2]

	t.Logf("read: median=%v threshold=%v", median, readRegressionThreshold)
	if median > readRegressionThreshold {
		t.Errorf("read regression: median %v exceeds threshold %v", median, readRegressionThreshold)
	}
}

func sortDurations(d []time.Duration) {
	for i := 1; i < len(d); i++ {
		for j := i; j > 0 && d[j] < d[j-1]; j-- {
			d[j], d[j-1] = d[j-1], d[j]
		}
	}
}
