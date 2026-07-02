//go:build !test

package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -framework LocalAuthentication -framework LocalAuthenticationEmbeddedUI -framework Foundation -framework AppKit -L${SRCDIR} -ltouchid
*/
import "C"
