package ssh

import (
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// FIXME: There must be a more idomatic way to do this, like using go:embed?
func keyPath(name string) string {
	dir, _ := filepath.Abs("../../testartifacts/testdata/keys/ssh")
	return path.Join(dir, name)
}

// Basic test to import the same rsa verifier from ssh public key and
// plaintext and encrypted private key (no password needed).
func TestImport(t *testing.T) {

	tests := []struct {
		keyName string
	}{
		{"rsa"},
		{"rsa_enc"},
		{"rsa.pub"},
	}

	for _, test := range tests {
		t.Run(test.keyName, func(t *testing.T) {
			path := keyPath(test.keyName)
			verifier, err := Import(path)
			if err != nil {
				t.Fatalf("Import(%s) error: %v", test.keyName, err)
			}
			assert.Equal(t,
				verifier.keyID,
				"SHA256:ESJezAOo+BsiEpddzRXS6+wtF16FID4NCd+3gj96rFo",
			)
		})

	}
}
