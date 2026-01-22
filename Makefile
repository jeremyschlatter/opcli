# Build opcli with Touch ID support
#
# Requirements:
# - Xcode Command Line Tools (clang, ar)
# - Go 1.21+
# - Apple Developer ID certificate (for codesigning)

# Set your signing identity here, or pass via command line:
#   make SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
SIGN_IDENTITY ?=

.PHONY: all clean sign

all: opcli

# Compile Objective-C Touch ID wrapper to static library
libtouchid.a: touchid.m
	clang -c -o touchid.o touchid.m -fobjc-arc -fmodules
	ar rcs libtouchid.a touchid.o
	rm -f touchid.o

# Build Go binary (requires libtouchid.a)
opcli: libtouchid.a *.go go.mod go.sum
	go build -o opcli .

# Sign the binary (required for Touch ID and Keychain ACL)
sign: opcli
ifndef SIGN_IDENTITY
	$(error SIGN_IDENTITY is not set. Run: make sign SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)")
endif
	codesign --sign "$(SIGN_IDENTITY)" --options runtime --force opcli

clean:
	rm -f opcli libtouchid.a touchid.o
