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

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

// FIXME: make this the interface for Keys in TUF metadata
type Key struct {
	KeyType string
	KeyVal  KeyVal
	Scheme  string
	keyID   string
}

type KeyVal struct {
	Public string
}

func (k *Key) Verify(ctx context.Context, data []byte, sig []byte) error {

	pub, err := parseSSH2Body(k.KeyVal.Public)
	if err != nil {
		return fmt.Errorf("failed to parse ssh public key material: %v", err)
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

func (k *Key) KeyID() (string, error) {
	return k.keyID, nil
}

// FIXME: required by dsse Verifier interface; consider fixing interface
func (k *Key) Public() crypto.PublicKey {
	sshKey, _ := parseSSH2Body(k.KeyVal.Public)
	return sshKey.(ssh.CryptoPublicKey).CryptoPublicKey()
}

// dsse.Signer interface implementation for ssh key signing
// Includes `Key` as single source of truth for signing scheme and keyid
type Signer struct {
	Key  *Key
	Path string
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
	return s.Key.keyID, nil
}

// Import Key from path using ssh-keygen
// Path can be public or private encrypted or plain key, much like git's
// user.signingKey config
func Import(path string) (*Key, error) {
	cmd := exec.Command("ssh-keygen", "-e", "-f", path)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run command %v: %v", cmd, err)
	}

	sshPub, err := parseSSH2Key(string(output))
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH2 key: %v", err)
	}

	return &Key{
		keyID:   ssh.FingerprintSHA256(sshPub),
		KeyType: "ssh",
		Scheme:  sshPub.Type(),
		KeyVal: KeyVal{
			Public: base64.StdEncoding.EncodeToString(sshPub.Marshal()),
		},
	}, nil
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
