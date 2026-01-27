# Build opcli with Touch ID support
#
# Requirements:
# - Xcode Command Line Tools (clang, ar)
# - Go 1.21+
# - Apple Developer ID certificate (for codesigning)

# Set your signing identity here, or pass via command line:
#   make SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
SIGN_IDENTITY ?=

# Version can be set via command line or defaults to git describe
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

.PHONY: all clean sign test

all: opcli

# Compile Objective-C Touch ID wrapper to static library
libtouchid.a: touchid.m
	clang -c -o touchid.o touchid.m -fobjc-arc -fmodules
	ar rcs libtouchid.a touchid.o
	rm -f touchid.o

# Compile TouchID stub for testing (always returns success)
libtouchid_stub.a: touchid_stub.m
	clang -c -o touchid_stub.o touchid_stub.m -fobjc-arc
	ar rcs libtouchid_stub.a touchid_stub.o
	rm -f touchid_stub.o

# Build Go binary (requires libtouchid.a)
opcli: libtouchid.a *.go go.mod go.sum
	go build -ldflags "-X main.Version=$(VERSION)" -o opcli .

# Build test binary with stubbed TouchID
opcli-test: libtouchid_stub.a *.go go.mod go.sum
	go build -tags test -ldflags "-X main.Version=$(VERSION)" -o opcli-test .

# Run e2e tests
test: opcli-test
	go test -tags test -v ./...

# Sign the binary (required for Touch ID and Keychain ACL)
sign: opcli
ifndef SIGN_IDENTITY
	$(error SIGN_IDENTITY is not set. Run: make sign SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)")
endif
	codesign --sign "$(SIGN_IDENTITY)" --options runtime --force opcli

clean:
	rm -f opcli opcli-test libtouchid.a libtouchid_stub.a touchid.o touchid_stub.o
