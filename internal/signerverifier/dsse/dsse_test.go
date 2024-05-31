// SPDX-License-Identifier: Apache-2.0

package dsse

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/gittuf/gittuf/internal/signerverifier/ssh"
	artifacts "github.com/gittuf/gittuf/internal/testartifacts"
	"github.com/gittuf/gittuf/internal/tuf"
	sslibdsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/assert"
)

func TestCreateEnvelope(t *testing.T) {
	rootMetadata := tuf.NewRootMetadata()
	env, err := CreateEnvelope(rootMetadata)
	assert.Nil(t, err)
	assert.Equal(t, PayloadType, env.PayloadType)
	assert.Equal(t, "eyJ0eXBlIjoicm9vdCIsInNwZWNfdmVyc2lvbiI6IjEuMCIsImNvbnNpc3RlbnRfc25hcHNob3QiOnRydWUsInZlcnNpb24iOjAsImV4cGlyZXMiOiIiLCJrZXlzIjpudWxsLCJyb2xlcyI6bnVsbH0=", env.Payload)
}

func TestSignEnvelope(t *testing.T) {
	// Setup test key
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "ecdsa")
	if err := os.WriteFile(keyPath, artifacts.SSHECDSAPrivate, 0o600); err != nil {
		t.Fatal(err)
	}

	signer, err := loadSSHSigner(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	env, err := createSignedEnvelope(signer)
	if err != nil {
		t.Fatal(err)
	}

	assert.Len(t, env.Signatures, 1)
	assert.Equal(t, "SHA256:oNYBImx035m3rl1Sn/+j5DPrlS9+zXn7k3mjNrC5eto", env.Signatures[0].KeyID)

	env, err = SignEnvelope(context.Background(), env, signer)
	assert.Nil(t, err)
	assert.Len(t, env.Signatures, 1)
	assert.Equal(t, "SHA256:oNYBImx035m3rl1Sn/+j5DPrlS9+zXn7k3mjNrC5eto", env.Signatures[0].KeyID)
}

func TestVerifyEnvelope(t *testing.T) {
	// Setup test key pair
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "rsa")
	keys := []struct {
		path string
		data []byte
	}{
		{keyPath, artifacts.SSHRSAPrivate},
		{keyPath + ".pub", artifacts.SSHRSAPublicSSH},
	}
	for _, key := range keys {
		if err := os.WriteFile(key.path, key.data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	signer, err := loadSSHSigner(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	env, err := createSignedEnvelope(signer)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, VerifyEnvelope(context.Background(), env, []sslibdsse.Verifier{signer.Key}, 1))
}

func loadSSHSigner(keyPath string) (*ssh.Signer, error) {
	key, err := ssh.Import(keyPath)
	if err != nil {
		return nil, err
	}

	signer := &ssh.Signer{
		Key:  key,
		Path: keyPath,
	}

	return signer, nil
}

func createSignedEnvelope(signer *ssh.Signer) (*sslibdsse.Envelope, error) {
	message := []byte("test payload")
	payload := base64.StdEncoding.EncodeToString(message)

	env := &sslibdsse.Envelope{
		PayloadType: "application/vnd.gittuf+text",
		Payload:     payload,
		Signatures:  []sslibdsse.Signature{},
	}

	env, err := SignEnvelope(context.Background(), env, signer)
	if err != nil {
		return nil, err
	}

	return env, nil
}
