package jws

import (
	"fmt"
	"crypto/rsa"
	"crypto/rand"
	"testing"
)

func TestRS256(t *testing.T) {
	rnd := rand.Reader
	key, _ := rsa.GenerateKey(rnd, 2048)
	rsAlg := NewRS256Algorithm(key, &key.PublicKey)

	signedMsg, _ := rsAlg.Sign([]byte(`{"iss":"http://gabriel.com"}`))
	fmt.Printf("signed message = %q", signedMsg)
	message, _ := rsAlg.Verify(signedMsg)
	fmt.Printf("unsigned message = %q", string(message))
}