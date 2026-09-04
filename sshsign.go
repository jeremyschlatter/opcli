package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// cmdSSHSign signs a file with an SSH private key stored in 1Password. It takes
// the same arguments as `ssh-keygen -Y sign`, so that a one-line wrapper can
// serve as git's gpg.ssh.program:
//
//	opcli ssh-sign <op://vault/item/field> -Y sign -n <namespace> -f <pubkey file> [-U] <file>
//
// The -f file must hold the public key matching the 1Password item (git writes
// user.signingkey there). The signature is written to <file>.sig in OpenSSH's
// SSHSIG format (see PROTOCOL.sshsig in the OpenSSH source).
func cmdSSHSign(args []string, accountFlag string) error {
	usage := fmt.Errorf("usage: opcli ssh-sign <op://ref> -Y sign -n <namespace> -f <pubkey file> [-U] <file>")
	if len(args) < 1 {
		return usage
	}
	ref := args[0]
	var namespace, pubkeyPath, path string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-Y":
			if i+1 >= len(args) || args[i+1] != "sign" {
				return usage
			}
			i++
		case "-n":
			if i+1 >= len(args) {
				return usage
			}
			namespace = args[i+1]
			i++
		case "-f":
			if i+1 >= len(args) {
				return usage
			}
			pubkeyPath = args[i+1]
			i++
		case "-U": // "use agent": meaningless here, but git passes it for literal signing keys
		default:
			if path != "" || strings.HasPrefix(args[i], "-") {
				return usage
			}
			path = args[i]
		}
	}
	if namespace == "" || pubkeyPath == "" || path == "" {
		return usage
	}

	pubkeyBytes, err := os.ReadFile(pubkeyPath)
	if err != nil {
		return err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubkeyBytes)
	if err != nil {
		return fmt.Errorf("parsing public key %s: %w", pubkeyPath, err)
	}
	message, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	aks, err := openKeychains(accountFlag, nil)
	if err != nil {
		return err
	}
	defer aks.Close()
	aks.pendingRefs = []string{ref}
	privkey, err := resolveRef(aks, ref, nil)
	if err != nil {
		return err
	}
	signer, err := ssh.ParsePrivateKey([]byte(privkey))
	if err != nil {
		return fmt.Errorf("parsing private key from %s: %w", ref, err)
	}
	if !bytes.Equal(signer.PublicKey().Marshal(), pub.Marshal()) {
		return fmt.Errorf("public key in %s does not match the private key in %s", pubkeyPath, ref)
	}

	hash := sha512.Sum512(message)
	signedData := append([]byte("SSHSIG"), ssh.Marshal(struct {
		Namespace, Reserved, HashAlg string
		Hash                         []byte
	}{namespace, "", "sha512", hash[:]})...)
	var sig *ssh.Signature
	if pub.Type() == ssh.KeyAlgoRSA {
		sig, err = signer.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, signedData, ssh.KeyAlgoRSASHA512)
	} else {
		sig, err = signer.Sign(rand.Reader, signedData)
	}
	if err != nil {
		return err
	}
	blob := append([]byte("SSHSIG"), ssh.Marshal(struct {
		Version                      uint32
		PublicKey                    []byte
		Namespace, Reserved, HashAlg string
		Signature                    []byte
	}{1, pub.Marshal(), namespace, "", "sha512", ssh.Marshal(sig)})...)

	b64 := base64.StdEncoding.EncodeToString(blob)
	var out strings.Builder
	out.WriteString("-----BEGIN SSH SIGNATURE-----\n")
	for len(b64) > 70 {
		out.WriteString(b64[:70])
		out.WriteByte('\n')
		b64 = b64[70:]
	}
	out.WriteString(b64)
	out.WriteString("\n-----END SSH SIGNATURE-----\n")
	return os.WriteFile(path+".sig", []byte(out.String()), 0644)
}
