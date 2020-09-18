package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
)

// Token represents a JWT token.
// See: https://tools.ietf.org/html/rfc7519
//
type Token struct {
	raw    []byte
	dot1   int
	dot2   int
	header Header
	// signature []byte
	// claims    json.RawMessage
}

func (t Token) String() string {
	return string(t.raw)
}

// Bytes representation of the token.
func (t Token) Bytes() []byte {
	return t.raw
}

// HeaderPart of the token (base64 encoded).
func (t Token) HeaderPart() []byte {
	return t.raw[:t.dot1]
}

// ClaimsPart of the token (base64 encoded).
func (t Token) ClaimsPart() []byte {
	return t.raw[t.dot1+1 : t.dot2]
}

// SignaturePart of the token (base64 encoded).
func (t Token) SignaturePart() []byte {
	return t.raw[t.dot2+1:]
}

// Header returns token's header.
func (t Token) Header() Header {
	return t.header
}

// DecodeClaims into the given container.
func (t Token) DecodeClaims(into interface{}) error {
	return json.Unmarshal(t.ClaimsPart(), into)
}

// DecodeClaims into the given container.
func (t Token) DecodedClaims() ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(t.ClaimsPart()))
}

// DecodeSignature into the given container.
func (t Token) DecodedSignature() ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(t.SignaturePart()))
}

// SecureString returns token without a signature (replaced with `.<signature>`).
// Deprecated: will be removed in v4
func (t *Token) SecureString() string {
	dot := bytes.LastIndexByte(t.raw, '.')
	return string(t.raw[:dot]) + `.<signature>`
}

// Raw returns token's raw bytes.
// Deprecated: will be removed in v4
func (t *Token) Raw() []byte {
	return t.raw
}

// RawHeader returns token's header raw bytes.
// Deprecated: will be removed in v4
func (t *Token) RawHeader() []byte {
	return t.raw[:t.dot1]
}

// RawClaims returns token's claims as a raw bytes.
// Deprecated: will be removed in v4
func (t *Token) RawClaims() []byte {
	c, _ := t.DecodedClaims()
	return c
}

// Payload returns token's payload.
func (t *Token) Payload() []byte {
	return t.raw[:t.dot2]
}

// Signature returns token's signature.
// Deprecated: will be removed in v4
func (t *Token) Signature() []byte {
	s, _ := t.DecodedSignature()
	return s
}

// Header is a JWT header.
// See: https://tools.ietf.org/html/rfc7519#section-5
//
type Header struct {
	Algorithm   Algorithm `json:"alg"`
	Type        string    `json:"typ,omitempty"` // only "JWT" can be here
	ContentType string    `json:"cty,omitempty"`
}

// MarshalJSON implements the json.Marshaler interface.
func (h *Header) MarshalJSON() ([]byte, error) {
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
	buf.WriteString(`"}`)

	return buf.Bytes(), nil
}
