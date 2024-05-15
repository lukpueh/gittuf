// SPDX-License-Identifier: Apache-2.0
package ssh

import (
	"crypto/rand"
	"fmt"
	"log"

	testdata "github.com/gittuf/gittuf/internal/testartifacts"
	"golang.org/x/crypto/ssh"
)

func SSHKeygen() {
	signer, err := ssh.ParsePrivateKeyWithPassphrase(
		testdata.SSHRSAPrivateEnc, []byte("hunter2"))
	if err != nil {
		log.Fatalf("Failed to parse private key: %s", err)
	}

	data := []byte("DATA")
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		log.Fatalf("Failed to sign: %s", err)
	}

	fmt.Println(sig)

}
