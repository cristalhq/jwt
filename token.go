package jwt

import "encoding/json"

// Token represents a JWT token.
type Token struct {
	raw       []byte
	header    Header
	claims    json.RawMessage
	payload   []byte
	signature []byte
}

// Raw returns token's raw bytes.
func (t *Token) Raw() []byte {
	return t.raw
}

// Header returns token's header.
func (t *Token) Header() Header {
	return t.header
}

// RawClaims returns token's claims as a raw bytes.
func (t *Token) RawClaims() []byte {
	return t.claims
}

// Payload returns token's payload.
func (t *Token) Payload() []byte {
	return t.payload
}

// Signature returns token's signature.
func (t *Token) Signature() []byte {
	return t.signature
}
