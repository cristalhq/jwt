package jwt

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
)

// Token represents a JWT token.
// See: https://tools.ietf.org/html/rfc7519
//
type Token struct {
	raw       []byte
	dot1      int
	dot2      int
	signature []byte
	header    Header
	claims    json.RawMessage
}

func (t *Token) String() string {
	return string(t.raw)
}

func (t *Token) Bytes() []byte {
	return t.raw
}

// HeaderPart returns token header part.
func (t *Token) HeaderPart() []byte {
	return t.raw[:t.dot1]
}

// ClaimsPart returns token claims part.
func (t *Token) ClaimsPart() []byte {
	return t.raw[t.dot1+1 : t.dot2]
}

// PayloadPart returns token payload part.
func (t *Token) PayloadPart() []byte {
	return t.raw[:t.dot2]
}

// SignaturePart returns token signature part.
func (t *Token) SignaturePart() []byte {
	return t.raw[t.dot2+1:]
}

// Header returns token's header.
func (t *Token) Header() Header {
	return t.header
}

// Claims returns token's claims.
func (t *Token) Claims() json.RawMessage {
	return t.claims
}

// DecodeClaims into a given parameter.
func (t *Token) DecodeClaims(dst interface{}) error {
	return json.Unmarshal(t.claims, dst)
}

// Signature returns token's signature.
func (t *Token) Signature() []byte {
	return t.signature
}

// unexported method to check that token was created via Parse func.
func (t *Token) isValid() bool {
	return t != nil && len(t.raw) > 0
}

// Header representa JWT header data.
// See: https://tools.ietf.org/html/rfc7519#section-5, https://tools.ietf.org/html/rfc7517
//
type Header struct {
	Algorithm   Algorithm `json:"alg"`
	Type        string    `json:"typ,omitempty"` // only "JWT" can be here
	ContentType string    `json:"cty,omitempty"`
	KeyID       string    `json:"kid,omitempty"`
}

// MarshalJSON implements the json.Marshaler interface.
func (h Header) MarshalJSON() ([]byte, error) {
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

// Generates a random key of the given bits length.
func GenerateRandomBits(bits int) ([]byte, error) {
	key := make([]byte, bits/8)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}
