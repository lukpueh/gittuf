// SPDX-License-Identifier: Apache-2.0
package ssh

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os/exec"
	"strings"

	"github.com/gittuf/gittuf/internal/third_party/go-securesystemslib/signerverifier"
	"github.com/gittuf/gittuf/internal/tuf"
	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

// dsse.Verifier interface implementation to be used with ssh Signer
// TODO: Check ssh signature format. If it isn't different from other rsa,
// ecdsa, ed25519 signature formats, we don't need a custom ssh Verifier.

// TODO: make sure this can be added to tuf metadata
type Verifier struct {
	keyID   string
	keyType string
	scheme  string
	public  crypto.PublicKey
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

func (v *Verifier) ToMetadata() (string, *signerverifier.SSLibKey, error) {
	sshPub, err := ssh.NewPublicKey(v.public)
	if err != nil {
		return "", nil, err
	}
	sshStr := base64.StdEncoding.EncodeToString(sshPub.Marshal())

	return v.keyID, &tuf.Key{
		KeyType: v.keyType,
		Scheme:  v.scheme,
		KeyVal: signerverifier.KeyVal{
			Public: sshStr,
		},
	}, nil
}
func FromMetadata(keyID string, key *signerverifier.SSLibKey) (*Verifier, error) {
	sshBytes, err := base64.StdEncoding.DecodeString(key.KeyVal.Public)
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.ParsePublicKey(sshBytes)
	if err != nil {
		return nil, err
	}
	sshCrypto := sshPub.(ssh.CryptoPublicKey).CryptoPublicKey()

	return &Verifier{
		keyID:   keyID,
		keyType: key.KeyType,
		scheme:  key.Scheme,
		public:  sshCrypto,
	}, nil
}

// dsse.Signer interface implementation for ssh key signing
// Includes verififier to have a single source of truth about signing scheme
// and keyid
// Uses ssh-keygen to sign with key from path
type Signer struct {
	Verifier *Verifier
	Path     string
}

func (s *Signer) Sign(ctx context.Context, data []byte) ([]byte, error) {
	// Call ssh-keygen command to create signature
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-n", "gittuf", "-f", s.Path)

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
	return s.Verifier.keyID, nil
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
	verifier.scheme = sshPub.Type()
	verifier.keyType = "ssh"

	return verifier, nil
}

func parseSSH2Body(body string) (ssh.PublicKey, error) {
	bodyBytes, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePublicKey(bodyBytes)
}

// Parse SSH2 public key as defined in RFC4716 (3.  Key File Format)
// Missing checks
// - line length
// - exact comment format
func parseSSH2Key(data string) (ssh.PublicKey, error) {

	header := "---- BEGIN SSH2 PUBLIC KEY ----"
	footer := "---- END SSH2 PUBLIC KEY ----"
	lineSep := "\n"
	commentSep := ":"
	continues := "\\"

	data = strings.Trim(data, lineSep)

	// Strip header and footer, fail if they don't exist
	lines := strings.Split(data, lineSep)
	if lines[0] != header {
		return nil, fmt.Errorf("missing header: %s", header)
	}
	last := len(lines) - 1
	if lines[last] != footer {
		return nil, fmt.Errorf("missing footer %s", footer)
	}
	lines = lines[1:last]

	// Strip comments
	var i int
	for i = 0; i < len(lines); i++ {
		if strings.Contains(lines[i], commentSep) {
			continue
		}
		// first line can not be a continued line
		if i > 0 && strings.HasSuffix(lines[i-1], continues) {
			continue
		}
		break
	}

	body := strings.Join(lines[i:], "")
	fmt.Println(body)
	return parseSSH2Body(body)
}
