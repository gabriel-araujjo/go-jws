package jws

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
)

func TestRS256(t *testing.T) {
	rnd := rand.Reader
	key, _ := rsa.GenerateKey(rnd, 2048)
	rsAlg := NewRS256Algorithm(key, &key.PublicKey)

	message := `{"iss":"http://example.com"}`

	signedMsg, err := rsAlg.Sign([]byte(message))
	if err != nil {
		t.Fatalf("unexpected error %q", err.Error())
	}
	fmt.Printf("signedMsg = %q", signedMsg)
	verifiedMessage, err := rsAlg.Verify(signedMsg)
	if err != nil {
		t.Fatalf("unexpected error %q", err.Error())
	}

	if string(verifiedMessage) != message {
		t.Fatalf("verified message : %q different of initial message %q", string(verifiedMessage), message)
	}
}
