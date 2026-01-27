//go:build test

// TouchID stub for testing - always returns success unless OPCLI_TEST_TOUCHID_FAIL is set
#include <stdlib.h>

int authenticateTouchID(const char *reason) {
    if (getenv("OPCLI_TEST_TOUCHID_FAIL")) {
        return 1;
    }
    return 0;
}
