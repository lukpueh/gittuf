// SPDX-License-Identifier: Apache-2.0
package ssh

import (
	"context"
	"crypto"
)

// dsse.Verifier interface implementation to be used with ssh Signer
// TODO: Check ssh signature format. If it isn't different from other rsa,
// ecdsa, ed25519 signature formats, we don't need a custom ssh Verifier.

// TODO: make sure this can be added to tuf metadata
type Verifier struct {
	keyID  string
	public *crypto.PublicKey
}

func (v *Verifier) Verify(ctx context.Context, data []byte, sig []byte) error {
	// Verify ssh signature byte stream using crypto stdlib
}
func (v *Verifier) KeyID() (string, error) {
	return v.keyID, nil
}
func (v *Verifier) Public() crypto.PublicKey {
	return s.public
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

	// Parse signature and return bytes

}
func (s *Signer) KeyID() (string, error) {
	return s.verifier.keyID, nil
}

// Import Verifier from path using ssh-keygen.
// Path can be public or private encrypted or plain key, much like git's
// user.signingKey config
// Currently only rsa is supported
func Import(path string) (*Verifier, error) {
	// Call ssh-keygen cmd to get x509/SPKI key data
	// 		ssh-keygen -f <path> -m pkcs8 -e

	// NOTE: `-m pkcs8` is only supported in the latest openssh versions for
	// ed25519 keys

	// Parse key data into crypto.PublicKey, if key type supported,
	// and assign to veriifer

	// Assign scheme for keytype
	// scheme must match scheme used by `ssh-keygen -Y sign`!!

	// Call ssh-keygen cmd to create a fingerprint
	// and assign to verifier
	//      ssh-kegen -f <path> -l

	// Return verifier
}
