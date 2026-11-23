// Secure Enclave key wrapping for opcli's stored credentials, exported to Go
// through a C ABI (see sealed.go).
//
// The SE key's dataRepresentation is an opaque handle that only this Mac's
// Secure Enclave can use; opcli keeps it in a plain file, so no keychain access
// group (and so no signing identity) is needed. The key's access control
// (Touch ID, with the fingers enrolled when it was made) is checked by the SEP
// itself when the private key is used, not by this process.
import CryptoKit
import Foundation
import LocalAuthentication
import Security

private let info = Data("opcli-se-wrap-v1".utf8)

// refused reports whether e means the user didn't authenticate: cancelled,
// failed, or couldn't be asked (no biometry, locked screen).
private func refused(_ e: Error) -> Bool {
    var ns: NSError? = e as NSError
    while let n = ns {
        if n.domain == LAErrorDomain { return true }
        if n.domain == NSOSStatusErrorDomain && [errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed].contains(OSStatus(n.code)) {
            return true
        }
        ns = n.userInfo[NSUnderlyingErrorKey] as? NSError
    }
    return false
}

// fail returns 2 if Touch ID didn't authenticate, 1 for any other error.
private func fail(_ err: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>, _ e: Error) -> Int32 {
    let ns = e as NSError
    err.pointee = strdup("\(e) [domain=\(ns.domain) code=\(ns.code)]")
    return refused(e) ? 2 : 1
}

private func give(_ d: Data, _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, _ outLen: UnsafeMutablePointer<Int>) {
    let p = UnsafeMutablePointer<UInt8>.allocate(capacity: max(d.count, 1))
    d.copyBytes(to: p, count: d.count)
    out.pointee = p
    outLen.pointee = d.count
}

private func kek(_ shared: SharedSecret, _ ephPub: Data, _ sePub: Data) -> SymmetricKey {
    shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: ephPub + sePub, sharedInfo: info, outputByteCount: 32)
}

// se_create makes a new SE P-256 key-agreement key that needs Touch ID, with
// the fingers enrolled now, for each use of its private key.
@_cdecl("se_create")
public func se_create(_ key: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, _ keyLen: UnsafeMutablePointer<Int>,
                      _ pub: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, _ pubLen: UnsafeMutablePointer<Int>,
                      _ err: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32 {
    guard SecureEnclave.isAvailable else {
        err.pointee = strdup("this Mac has no Secure Enclave")
        return 1
    }
    var cfErr: Unmanaged<CFError>?
    guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &cfErr) else {
        return fail(err, cfErr!.takeRetainedValue() as Error)
    }
    do {
        let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
        give(k.dataRepresentation, key, keyLen)
        give(k.publicKey.x963Representation, pub, pubLen)
        return 0
    } catch {
        return fail(err, error)
    }
}

// se_wrap seals msg to an SE public key. It uses only the public key, so it
// never prompts. Blob: ephemeral public key (65 bytes) || AES-GCM combined.
@_cdecl("se_wrap")
public func se_wrap(_ pub: UnsafePointer<UInt8>, _ pubLen: Int,
                    _ msg: UnsafePointer<UInt8>, _ msgLen: Int,
                    _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, _ outLen: UnsafeMutablePointer<Int>,
                    _ err: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32 {
    do {
        let sePub = Data(bytes: pub, count: pubLen)
        let recipient = try P256.KeyAgreement.PublicKey(x963Representation: sePub)
        let eph = P256.KeyAgreement.PrivateKey()
        let ephPub = eph.publicKey.x963Representation
        let shared = try eph.sharedSecretFromKeyAgreement(with: recipient)
        let box = try AES.GCM.seal(Data(bytes: msg, count: msgLen), using: kek(shared, ephPub, sePub))
        give(ephPub + box.combined!, out, outLen)
        return 0
    } catch {
        return fail(err, error)
    }
}

// se_unwrap opens a blob with the SE key. The ECDH runs inside the SEP, which
// demands Touch ID first, showing reason. It also returns the key's public
// key, for sealing again without trusting a public key read from disk.
@_cdecl("se_unwrap")
public func se_unwrap(_ key: UnsafePointer<UInt8>, _ keyLen: Int,
                      _ blob: UnsafePointer<UInt8>, _ blobLen: Int,
                      _ reason: UnsafePointer<CChar>,
                      _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, _ outLen: UnsafeMutablePointer<Int>,
                      _ pub: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, _ pubLen: UnsafeMutablePointer<Int>,
                      _ err: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32 {
    guard blobLen > 65 else {
        err.pointee = strdup("sealed credentials are truncated")
        return 1
    }
    do {
        let ctx = LAContext()
        ctx.localizedReason = String(cString: reason)
        let se = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: Data(bytes: key, count: keyLen), authenticationContext: ctx)
        let sePub = se.publicKey.x963Representation
        let b = Data(bytes: blob, count: blobLen)
        let ephPub = b.prefix(65)
        let shared = try se.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: ephPub))
        let plain = try AES.GCM.open(AES.GCM.SealedBox(combined: b.dropFirst(65)), using: kek(shared, ephPub, sePub))
        give(plain, out, outLen)
        give(sePub, pub, pubLen)
        return 0
    } catch {
        return fail(err, error)
    }
}
