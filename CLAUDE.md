@README.md

NOTE: The release signing key is not kept on my Mac, so `make sign` only works in CI, and a local build of opcli can't reach its keychain items. Test locally with `make test`: without a signing identity it runs unsigned, against the test fixtures, with credentials kept in files. To try a real build, cut a pre-release (a tag with a hyphen, like `v0.24.0-pre1`) and install that.

NOTE: Always use `make test` to run tests (not `go test ./...`).
