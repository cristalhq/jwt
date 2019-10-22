package jwt

import (
	"bytes"
	"encoding/json"
)

// Header stores JWT header data.
// see https://tools.ietf.org/html/rfc7515
// and https://tools.ietf.org/html/rfc7519
type Header struct {
	Algorithm   Algorithm `json:"alg"`
	Type        string    `json:"typ,omitempty"` // type of JWS: it can only be "JWT" here
	ContentType string    `json:"cty,omitempty"`
	KeyID       string    `json:"kid,omitempty"`
}

// MarshalJSON ...
func (h *Header) MarshalJSON() (data []byte, err error) {
	buf := bytes.Buffer{}
	buf.WriteString(`{"alg":"`)
	buf.WriteString(string(h.Algorithm))

	if h.Type != "" {
		buf.WriteString(`","typ":"`)
		buf.WriteString(h.Type)
	}
	if h.ContentType != "" {
		buf.WriteString(`","cty":"`)
		buf.WriteString(h.ContentType)
	}
	if h.KeyID != "" {
		buf.WriteString(`","kid":"`)
		buf.WriteString(h.KeyID)
	}
	buf.WriteString(`"}`)

	return buf.Bytes(), nil
}

// Signer used to sign and verify tokens.
type Signer interface {
	Algorithm() Algorithm
	Sign(payload []byte) ([]byte, error)
	Verify(expected, payload []byte) error
}

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

// MarshalBinary implements encoding.BinaryMarshaler.
func (t *Token) MarshalBinary() (data []byte, err error) {
	return t.raw, nil
}
