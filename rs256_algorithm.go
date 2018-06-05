package jws

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

type rs256Algorithm struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	base64Head []byte
}

// NewRS256Algorithm creates a jws RSA PKCS1v15 using sha-256 hash
func NewRS256Algorithm(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) Algorithm {
	return &rs256Algorithm{publicKey: publicKey, privateKey: privateKey}
}

func (a rs256Algorithm) Algorithm() string {
	return "RS256"
}

// encodeHeader returns the base64 representationOf the header
func (a *rs256Algorithm) encodeHeader() []byte {
	if a.base64Head != nil {
		return a.base64Head
	}
	if a.publicKey == nil {
		src := []byte("null")
		dst := make([]byte, base64.URLEncoding.EncodedLen(len(src)))
		base64.URLEncoding.Encode(dst, src)
		return dst
	}
	n := base64.URLEncoding.EncodeToString(a.publicKey.N.Bytes())
	e := base64.URLEncoding.EncodeToString(big.NewInt(int64(a.publicKey.E)).Bytes())
	jsonHeader := fmt.Sprintf(`{"alg":"RS256","jwk":{"alg":"RS256","key_ops":["verify"],"kty":"RSA","n":%q,"e":%q}}`, n, e)
	a.base64Head = make([]byte, base64.URLEncoding.EncodedLen(len(jsonHeader)))
	base64.URLEncoding.Encode(a.base64Head, []byte(jsonHeader))
	return a.base64Head
}

func (a *rs256Algorithm) Sign(data []byte) (string, error) {
	if a.privateKey == nil {
		return "", errors.New("nil private key")
	}

	e := base64.URLEncoding
	rng := rand.Reader

	cursor := 0
	header := a.encodeHeader()
	signedMessage := make([]byte,
		len(header)+
			e.EncodedLen(len(data))+
			e.EncodedLen((a.privateKey.N.BitLen() + 7) / 8)+
			2 /*dots between the three parts*/)

	fmt.Printf("len(header) = %d\n", len(header))
	cursor += copy(signedMessage[cursor:], header)
	fmt.Printf("cursor = %d\n", cursor)
	signedMessage[cursor] = '.'
	cursor++
	fmt.Printf("cursor = %d\n", cursor)

	base64.URLEncoding.Encode(signedMessage[cursor:], data)
	cursor += e.EncodedLen(len(data))

	fmt.Printf("message yet %q", string(signedMessage[:cursor]))

	digest := sha256.Sum256(signedMessage[:cursor])

	signature, err := rsa.SignPKCS1v15(rng, a.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}

	signedMessage[cursor] = '.'
	cursor++

	fmt.Printf("cursor = %d\n", cursor)

	fmt.Printf("signature %q\n", base64.URLEncoding.EncodeToString(digest[:]))
	fmt.Printf("sha256.Size %d, digest size %d, signature %d\n", sha256.Size, len(digest), len(signature))

	base64.URLEncoding.Encode(signedMessage[cursor:], signature)
	return string(signedMessage), nil
}

func (a *rs256Algorithm) Verify(message string) ([]byte, error) {
	cursor := strings.LastIndexByte(message, '.')

	if cursor == -1 {
		return nil, errors.New("invalid message")
	}

	digest := sha256.Sum256([]byte(message[:cursor]))

	err := rsa.VerifyPKCS1v15(a.publicKey, crypto.SHA3_256, digest[:], []byte(message[cursor+1:]))

	if err != nil {
		return nil, err
	}

	payloadPos := strings.IndexByte(message, '.') + 1

	return base64.URLEncoding.DecodeString(message[payloadPos:cursor])
}
