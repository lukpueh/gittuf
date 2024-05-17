// SPDX-License-Identifier: Apache-2.0
package ssh

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os/exec"
	"strings"
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
	// Verify ssh signature byte stream using crypto stdlib
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
	// 		ssh-keygen -f <s.path> -y sign

	// Handle errors (key not found, etc.)

	sig := []byte("")

	// Parse signature and return bytes
	return sig, nil

}
func (s *Signer) KeyID() (string, error) {
	return s.verifier.keyID, nil
}

func runCommand(command string) ([]byte, error) {
	parts := strings.Fields(command)
	cmd := exec.Command(parts[0], parts[1:]...)
	return cmd.Output()

}

// Import Verifier from path using ssh-keygen
//   - Path can be public or private encrypted or plain key, much like git's
//     user.signingKey config
//   - Currently only rsa is supported
func Import(path string) (*Verifier, error) {
	// Call ssh-keygen cmd to get x509/SPKI key data
	// NOTE: `-m pkcs8` is only supported in the latest openssh versions for
	// ed25519 keys
	command := "ssh-keygen -m pkcs8 -e -f " + path
	output, err := runCommand(command)
	if err != nil {
		return nil, fmt.Errorf("failed to run command %v: %v", command, err)
	}

	block, _ := pem.Decode(output)
	if block == nil {
		return nil, fmt.Errorf("failed to run decode pem")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	switch k := pub.(type) {
	case *rsa.PublicKey:
		fmt.Println("success!")
		// TODO: Create SSlibKey, assign scheme for keytype
		// scheme must match scheme used by `ssh-keygen -Y sign`!!

	default:
		return nil, fmt.Errorf("unsupported key type: %T", k)
	}

	// Call ssh-keygen cmd to create a fingerprint to be used as keyid
	command = "ssh-keygen -l -f " + path
	output, err = runCommand(command)
	if err != nil {
		return nil, fmt.Errorf("failed to run command %v: %v", command, err)
	}

	trimmed := strings.TrimSpace(string(output[:]))
	parts := strings.Split(trimmed, " ")
	if len(parts) < 2 {
		return nil, fmt.Errorf("unexepcted key fingerpring: %v", trimmed)
	}
	keyid := parts[1]

	return &Verifier{
		keyID:  keyid,
		public: pub.(*rsa.PublicKey),
	}, nil

}
