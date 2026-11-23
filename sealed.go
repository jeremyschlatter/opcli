//go:build !test

package main

// The Secure Enclave primitives, from sep.swift. The Makefile builds libsep.a
// and passes it, with the Swift runtime's library paths, in CGO_LDFLAGS (see
// there for why not here).

/*
#cgo LDFLAGS: -framework CryptoKit -framework LocalAuthentication -framework Security -framework Foundation
#include <stdlib.h>
#include <stdint.h>
int se_create(uint8_t **key, long *keyLen, uint8_t **pub, long *pubLen, char **err);
int se_wrap(const uint8_t *pub, long pubLen, const uint8_t *msg, long msgLen, uint8_t **out, long *outLen, char **err);
int se_unwrap(const uint8_t *key, long keyLen, const uint8_t *blob, long blobLen, const char *reason,
              uint8_t **out, long *outLen, uint8_t **pub, long *pubLen, char **err);
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

func seTake(p *C.uint8_t, n C.long) []byte {
	b := C.GoBytes(unsafe.Pointer(p), C.int(n))
	C.free(unsafe.Pointer(p))
	return b
}

func seErr(rc C.int, cerr *C.char) error {
	if rc == 0 {
		return nil
	}
	msg := C.GoString(cerr)
	C.free(unsafe.Pointer(cerr))
	if rc == 2 {
		return fmt.Errorf("%w (%s)", ErrAuthRefused, msg)
	}
	return errors.New("secure enclave: " + msg)
}

func sePtr(b []byte) *C.uint8_t { return (*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(b))) }

// seCreate makes a new Secure Enclave key that needs Touch ID to use. key is
// its opaque handle, usable only by this Mac's Secure Enclave.
func seCreate() (key, pub []byte, err error) {
	var k, p *C.uint8_t
	var kn, pn C.long
	var cerr *C.char
	if err := seErr(C.se_create(&k, &kn, &p, &pn, &cerr), cerr); err != nil {
		return nil, nil, err
	}
	return seTake(k, kn), seTake(p, pn), nil
}

// seWrap seals msg to the public key pub. It never prompts.
func seWrap(pub, msg []byte) ([]byte, error) {
	var o *C.uint8_t
	var on C.long
	var cerr *C.char
	if err := seErr(C.se_wrap(sePtr(pub), C.long(len(pub)), sePtr(msg), C.long(len(msg)), &o, &on, &cerr), cerr); err != nil {
		return nil, err
	}
	return seTake(o, on), nil
}

// seUnwrap opens blob with the key, after the Secure Enclave has had Touch ID,
// whose prompt shows reason. It returns the key's public key too.
func seUnwrap(key, blob []byte, reason string) (msg, pub []byte, err error) {
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))
	var o, p *C.uint8_t
	var on, pn C.long
	var cerr *C.char
	if err := seErr(C.se_unwrap(sePtr(key), C.long(len(key)), sePtr(blob), C.long(len(blob)), cReason, &o, &on, &p, &pn, &cerr), cerr); err != nil {
		return nil, nil, err
	}
	return seTake(o, on), seTake(p, pn), nil
}
