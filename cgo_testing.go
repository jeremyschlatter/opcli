//go:build test

package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -framework LocalAuthentication -framework Foundation ${SRCDIR}/libtouchid_stub.a
*/
import "C"
