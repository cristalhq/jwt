package jwt

import (
	"bytes"
	"encoding/base64"
)

var b64DecodeStr = base64.RawURLEncoding.DecodeString

// Token represents a JWT token.
// See: https://tools.ietf.org/html/rfc7519
//
type Token struct {
	raw    []byte
	dot1   int
	dot2   int
	header Header
	claims []byte
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

// PayloadPart returns token's payload.
func (t *Token) PayloadPart() []byte {
	return t.raw[:t.dot2]
}

// SignaturePart of the token (base64 encoded).
func (t Token) SignaturePart() []byte {
	return t.raw[t.dot2+1:]
}

// Header returns token's header.
func (t Token) Header() Header {
	return t.header
}

// Claims into the given container.
func (t Token) Claims() []byte {
	return t.claims
}

// Signature into the given container.
func (t Token) Signature() []byte {
	s, _ := b64DecodeStr(string(t.SignaturePart()))
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
