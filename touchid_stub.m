//go:build test

// TouchID stub for testing - always returns success unless OPCLI_TEST_TOUCHID_FAIL is set
#include <stdlib.h>
#include <stdio.h>

int authenticateTouchID(const char *reason) {
    if (getenv("OPCLI_TEST_TOUCHID_FAIL")) {
        return 1;
    }
    // Output reason to stderr so e2e tests can verify the biometric prompt content
    fprintf(stderr, "TouchID reason: %s\n", reason);
    return 0;
}
