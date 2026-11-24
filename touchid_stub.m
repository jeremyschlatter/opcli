//go:build test

// TouchID stub for testing - always returns success unless OPCLI_TEST_TOUCHID_FAIL is set.
// If OPCLI_TEST_TOUCHID_LOG names a file, each prompt appends its payload to it as a line.
#include <stdio.h>
#include <stdlib.h>

int authenticateTouchID(const char *reason, const char *payloadJSON,
                        const void *iconPNG, int iconPNGLen, void **keyContext) {
    (void)reason;
    if (keyContext) *keyContext = NULL;
    (void)iconPNG;
    (void)iconPNGLen;
    const char *log = getenv("OPCLI_TEST_TOUCHID_LOG");
    if (log) {
        FILE *f = fopen(log, "a");
        if (!f) abort();
        fprintf(f, "%s\n", payloadJSON);
        fclose(f);
    }
    if (getenv("OPCLI_TEST_TOUCHID_FAIL")) {
        return 1;
    }
    return 0;
}
