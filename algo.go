package jwt

import (
	"crypto"
	_ "crypto/sha256" // to register a hash
	_ "crypto/sha512" // to register a hash
)

func init() {
	if !crypto.SHA256.Available() {
		panic("crypto.SHA256 is not available")
	}
	if !crypto.SHA384.Available() {
		panic("crypto.SHA384 is not available")
	}
	if !crypto.SHA512.Available() {
		panic("crypto.SHA512 is not available")
	}
}

// Algorithm for signing and verifying.
type Algorithm string

// Algorithm names for signing and verifying.
const (
	NoEncryption Algorithm = "none"

	HS256 Algorithm = "HS256"
	HS384 Algorithm = "HS384"
	HS512 Algorithm = "HS512"

	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"

	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"

	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
)
