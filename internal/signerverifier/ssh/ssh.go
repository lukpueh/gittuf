// SPDX-License-Identifier: Apache-2.0
package ssh

import (
	"bytes"
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

	if err := rsa.VerifyPKCS1v15(v.public.(*rsa.PublicKey), crypto.SHA256, data, sig); err != nil {
		fmt.Println(err)
	}

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

	switch k := pub.(type) {
	case *rsa.PublicKey:
		fmt.Println("success!")
		// TODO: Create SSlibKey, assign scheme for keytype
		// scheme must match scheme used by `ssh-keygen -Y sign`!!

	default:
		return nil, fmt.Errorf("unsupported key type: %T", k)
	}

	// Call ssh-keygen cmd to create a fingerprint to be used as keyid
	cmd = exec.Command("ssh-keygen", "-l", "-f", path)
	output, err = cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run command %v: %v", cmd, err)
	}

	trimmed := strings.TrimSpace(string(output[:]))
	parts := strings.Split(trimmed, " ")
	if len(parts) < 2 {
		return nil, fmt.Errorf("unexepcted key fingerprint: %v", trimmed)
	}
	keyid := parts[1]

	return &Verifier{
		keyID:  keyid,
		public: pub.(*rsa.PublicKey),
	}, nil

}
