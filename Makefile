# Build opcli with Touch ID support
#
# Requirements:
# - Xcode Command Line Tools (clang, ar, swiftc)
# - Go 1.21+
# - Apple Developer ID certificate (for codesigning), plus a provisioning
#   profile and entitlements for it in macos/ (the ones checked in are mine)

# Set your signing identity here, or pass via command line:
#   make SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
SIGN_IDENTITY ?=
export SIGN_IDENTITY

# Version can be set via command line or defaults to git describe
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# LAAuthenticationView (the inline TouchID UI in touchid.m) requires macOS
# 12+, so pin the deployment target here. MACOSX_DEPLOYMENT_TARGET is read
# by the plain `clang` invocation below; CGO_CFLAGS carries the same floor
# into go build / go test (which otherwise inherit whatever MACOSX_DEPLOYMENT_TARGET
# is set in the shell — e.g. 11.3 from a nix shell).
MACOS_MIN := 12.0
export MACOSX_DEPLOYMENT_TARGET := $(MACOS_MIN)
export CGO_CFLAGS := -mmacosx-version-min=$(MACOS_MIN)

# The Secure Enclave code (sep.swift) goes in through CGO_LDFLAGS, with the
# search paths for the Swift runtime, which depend on the installed Xcode.
# #cgo LDFLAGS won't do: cmd/go refuses a Swift library named there (it has an
# __LLVM section), so keep it out of any -L directory named there, too.
SDK := $(shell xcrun --show-sdk-path)
SWIFT_LIB := $(shell dirname $$(xcrun -f swiftc))/../lib/swift/macosx
export CGO_LDFLAGS := $(CURDIR)/libsep.a -L$(SDK)/usr/lib/swift -L$(SWIFT_LIB)

.PHONY: all clean sign sign-test test update-plugins

all: opcli

# Compile Objective-C Touch ID wrapper to static library
libtouchid.a: touchid.m
	clang -c -o touchid.o touchid.m -fobjc-arc -fmodules -Wno-deprecated-declarations
	ar rcs libtouchid.a touchid.o
	rm -f touchid.o

# Compile the Secure Enclave key wrapping (sep.swift) to a static library
libsep.a: sep.swift
	swiftc -O -parse-as-library -emit-library -static -module-name sep \
		-target $(shell uname -m)-apple-macos$(MACOS_MIN) -o libsep.a sep.swift

# Compile TouchID stub for testing (always returns success)
libtouchid_stub.a: touchid_stub.m
	clang -c -o touchid_stub.o touchid_stub.m -fobjc-arc
	ar rcs libtouchid_stub.a touchid_stub.o
	rm -f touchid_stub.o

# Build Go binary (requires libtouchid.a)
opcli: libtouchid.a libsep.a $(shell find . -name '*.go') migrations/sql/*.sql go.mod go.sum
	go generate
	go build -ldflags "-X main.Version=$(VERSION)" -o opcli .
	@rm -f obfuscation.go

# Build test binary with stubbed TouchID
opcli-test: libtouchid_stub.a libsep.a $(shell find . -name '*.go') migrations/sql/*.sql go.mod go.sum
	go generate
	go build -tags test -ldflags "-X main.Version=$(VERSION)" -o opcli-test .
	@rm -f obfuscation.go

# Run unit and e2e tests. With SIGN_IDENTITY set, they run from signed bundles
# against the real keychain. Without it, the keychain tests are skipped and
# the e2e tests keep their credentials in files.
test: libtouchid.a libsep.a
	go generate
ifdef SIGN_IDENTITY
	go test -exec $(CURDIR)/scripts/exec-test-bundled ./...
else
	go test ./...
endif
	@rm -f obfuscation.go

# Pull the latest upstream shell plugins (for `opcli plugin`)
update-plugins:
	go get github.com/1Password/shell-plugins@main
	scripts/gen-plugin-registry
	go mod tidy

# Build opcli.app, the signed bundle. An unsigned opcli can't reach its
# keychain items (see scripts/bundle). Run it as opcli.app/Contents/MacOS/opcli,
# directly or through a symlink.
sign: opcli
ifndef SIGN_IDENTITY
	$(error SIGN_IDENTITY is not set. Run: make sign SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)")
endif
	scripts/bundle opcli opcli opcli.app

# Same for the test binary
sign-test: opcli-test
ifndef SIGN_IDENTITY
	$(error SIGN_IDENTITY is not set)
endif
	scripts/bundle opcli-test opcli-test opcli-test.app

clean:
	rm -rf opcli.app opcli-test.app
	rm -f opcli opcli-test libtouchid.a libtouchid_stub.a libsep.a touchid.o touchid_stub.o
