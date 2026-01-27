//go:build !test

package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -framework LocalAuthentication -framework Foundation -L${SRCDIR} -ltouchid
*/
import "C"
