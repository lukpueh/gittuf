package ssh

import (
	"context"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// FIXME: There must be a more idomatic way to do this, like using go:embed?
func testDataPath(name string) string {
	dir, _ := filepath.Abs("../../testartifacts/testdata/")
	return path.Join(dir, name)
}

// Basic test to import the same rsa verifier from ssh public key and
// plaintext and encrypted private key (no password needed).
func TestImport(t *testing.T) {

	rsa_keyid := "SHA256:ESJezAOo+BsiEpddzRXS6+wtF16FID4NCd+3gj96rFo"
	ecdsa_keyid := "SHA256:oNYBImx035m3rl1Sn/+j5DPrlS9+zXn7k3mjNrC5eto"

	// TODO: Uncommented encrypted key test. This works but is difficult to
	// test because it requires mocking stdin for the password only but not for
	// the input data to be signed
	tests := []struct {
		keyName string
		keyID   string
	}{
		{"rsa", rsa_keyid},
		{"rsa_enc", rsa_keyid},
		{"rsa.pub", rsa_keyid},
		{"ecdsa", ecdsa_keyid},
		{"ecdsa_enc", ecdsa_keyid},
		{"ecdsa.pub", ecdsa_keyid},
	}

	for _, test := range tests {
		t.Run(test.keyName, func(t *testing.T) {
			if strings.Contains(test.keyName, "_enc") {
				t.Setenv("SSH_ASKPASS", testDataPath("scripts/askpass.sh"))
				t.Setenv("SSH_ASKPASS_REQUIRE", "force")
			}

			path := testDataPath("keys/ssh/" + test.keyName)
			verifier, err := Import(path)
			if err != nil {
				t.Fatalf("Import(%s) error: %v", test.keyName, err)
			}
			assert.Equal(t,
				verifier.keyID,
				test.keyID,
			)

			signer := Signer{
				verifier: verifier,
				path:     path,
			}

			data := []byte("DATA")
			sig, err := signer.Sign(context.TODO(), data)
			if err != nil {
				t.Fatalf("Sign() error with key %s: %v", test.keyName, err)
			}

			err = verifier.Verify(context.TODO(), data, sig)
			if err != nil {
				t.Fatalf("Verifiy() error with key %s: %v", test.keyName, err)
			}
		})

	}
}
