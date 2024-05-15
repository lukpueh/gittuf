// SPDX-License-Identifier: Apache-2.0
package ssh

import (
	"crypto/rsa"
	"fmt"
	"log"
	"net"
	"os"

	testdata "github.com/gittuf/gittuf/internal/testartifacts"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func SSHKeygen() {
	priv, err := ssh.ParseRawPrivateKeyWithPassphrase(
		testdata.SSHRSAPrivateEnc, []byte("hunter2"))
	if err != nil {
		log.Fatalf("Failed to parse private key: %s", err)
	}

	// ssh-agent(1) provides a UNIX socket at $SSH_AUTH_SOCK.
	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatalf("Failed to open SSH_AUTH_SOCK: %v", err)
	}

	client := agent.NewClient(conn)

	if err = client.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		log.Fatalf("Failed to add private key: %s", err)
	}

	privRsa, _ := priv.(*rsa.PrivateKey)
	sshPub, _ := ssh.NewPublicKey(&privRsa.PublicKey)

	data := []byte("DATA")
	sig, err := client.Sign(sshPub, data)

	if err != nil {
		log.Fatalf("Failed to sign: %s", err)
	}

	fmt.Println(sig)

}
