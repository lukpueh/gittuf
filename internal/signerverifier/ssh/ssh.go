// SPDX-License-Identifier: Apache-2.0
package ssh

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"

	"github.com/gittuf/gittuf/internal/third_party/go-securesystemslib/signerverifier"
	"github.com/gittuf/gittuf/internal/tuf"
	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

type Verifier struct {
	keyID   string
	keyType string
	scheme  string
	public  crypto.PublicKey
}

func (v *Verifier) Verify(ctx context.Context, data []byte, sig []byte) error {

	pub, err := ssh.NewPublicKey(v.public)
	if err != nil {
		return fmt.Errorf("failed to parse ssh public key: %v", err)
	}

	signature, err := sshsig.Unarmor(sig)
	if err != nil {
		return fmt.Errorf("failed to parse ssh signature: %v", err)
	}

	message := bytes.NewReader(data)

	// ssh-keygen uses sha512 to sign with **any*** key
	hash := sshsig.HashSHA512
	if err = sshsig.Verify(message, signature, pub, hash, "gittuf"); err != nil {
		return fmt.Errorf("failed to verify ssh signature: %v", err)
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

	sshPub, err := parseSSH2Body(key.KeyVal.Public)
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
// Path can be public or private encrypted or plain key, much like git's
// user.signingKey config
func Import(path string) (*Verifier, error) {
	cmd := exec.Command("ssh-keygen", "-e", "-f", path)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run command %v: %v", cmd, err)
	}

	sshPub, err := parseSSH2Key(string(output))
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH2 key: %v", err)
	}

	var verifier *Verifier
	verifier = new(Verifier)

	verifier.keyID = ssh.FingerprintSHA256(sshPub)
	verifier.scheme = sshPub.Type()
	verifier.keyType = "ssh"
	verifier.public = sshPub.(ssh.CryptoPublicKey).CryptoPublicKey()

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
// Ignores:
// - line length constraints
// - other line termination charcters than "\n"
// - exact header tag and header value format
func parseSSH2Key(data string) (ssh.PublicKey, error) {

	header := "---- BEGIN SSH2 PUBLIC KEY ----"
	footer := "---- END SSH2 PUBLIC KEY ----"
	lineSep := "\n"
	commentSep := ":"
	continues := "\\"

	data = strings.Trim(data, lineSep)

	// Strip header and footer
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
		// Skip i==1, first line can not be a continued line
		if i > 0 && strings.HasSuffix(lines[i-1], continues) {
			continue
		}
		break
	}

	// Parse key material
	body := strings.Join(lines[i:], "")
	return parseSSH2Body(body)
}
