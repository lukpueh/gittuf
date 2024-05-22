// SPDX-License-Identifier: Apache-2.0
package ssh

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os/exec"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

// dsse.Verifier interface implementation to be used with ssh Signer
// TODO: Check ssh signature format. If it isn't different from other rsa,
// ecdsa, ed25519 signature formats, we don't need a custom ssh Verifier.

// TODO: make sure this can be added to tuf metadata
type Verifier struct {
	keyID  string
	public crypto.PublicKey
}

func (v *Verifier) Verify(ctx context.Context, data []byte, sig []byte) error {

	pub, err := ssh.NewPublicKey(v.public)
	if err != nil {
		return fmt.Errorf("failed to create ssh public key instance: %v", err)
	}

	signature, err := sshsig.Unarmor(sig)
	if err != nil {
		return fmt.Errorf("failed to create ssh signature instance: %v", err)
	}

	message := bytes.NewReader(data)

	// This is the default hash algorithm used in Sign for any key
	hash := sshsig.HashSHA512
	if err = sshsig.Verify(message, signature, pub, hash, "gittuf"); err != nil {
		return fmt.Errorf("failed to verify signature: %v", err)
	}

	return nil
}
func (v *Verifier) KeyID() (string, error) {
	return v.keyID, nil
}
func (v *Verifier) Public() crypto.PublicKey {
	return v.public
}

// dsse.Signer interface implementation for ssh key signing
// Includes verififier to have a single source of truth about signing scheme
// and keyid
// Uses ssh-keygen to sign with key from path
type Signer struct {
	verifier *Verifier
	path     string
}

func (s *Signer) Sign(ctx context.Context, data []byte) ([]byte, error) {
	// Call ssh-keygen command to create signature
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-n", "gittuf", "-f", s.path)

	cmd.Stdin = bytes.NewBuffer(data)

	output, err := cmd.Output()
	if err != nil {
		// TODO: Handle signing error (exit 255) on world-readable key file
		//    git doesn't store read permissions; maybe need to chmod in test
		return nil, fmt.Errorf("failed to run command %v: %v", cmd, err)
	}

	return output, nil

}

func (s *Signer) KeyID() (string, error) {
	return s.verifier.keyID, nil
}

// Import Verifier from path using ssh-keygen
//   - Path can be public or private encrypted or plain key, much like git's
//     user.signingKey config
//   - Currently only rsa is supported
func Import(path string) (*Verifier, error) {
	// Call ssh-keygen cmd to get x509/SPKI key data
	// NOTE: `-m pkcs8` is only supported in the latest openssh versions for
	// ed25519 keys
	cmd := exec.Command("ssh-keygen", "-m", "pkcs8", "-e", "-f", path)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run command %v: %v", cmd, err)
	}

	block, _ := pem.Decode(output)
	if block == nil {
		return nil, fmt.Errorf("failed to run decode pem")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}
	var verifier *Verifier
	verifier = new(Verifier)

	switch k := pub.(type) {
	case *rsa.PublicKey:
		verifier.public = k

	case *ecdsa.PublicKey:
		verifier.public = k

	default:
		return nil, fmt.Errorf("unsupported key type: %T", k)
	}

	sshPub, _ := ssh.NewPublicKey(verifier.public)
	verifier.keyID = ssh.FingerprintSHA256(sshPub)

	return verifier, nil
}
