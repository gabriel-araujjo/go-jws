package jws

// Signer provides a Sign method to generate a jws
type Signer interface {
	Sign([]byte) (string, error)
}

// Verifier provides a Verify method to verify signatures
type Verifier interface {
	Verify(string) ([]byte, error)
}

// Algorithm is a Signer and Verifier with a name
type Algorithm interface {
	Signer
	Verifier
	Algorithm() string
}