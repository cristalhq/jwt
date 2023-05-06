package jwt

import (
	"encoding/base64"
	"encoding/json"
)

// BuilderOption is used to modify builder properties.
type BuilderOption func(*Builder)

// WithKeyID sets `kid` header for token.
func WithKeyID(kid string) BuilderOption {
	return func(b *Builder) { b.header.KeyID = kid }
}

// WithContentType sets `cty` header for token.
func WithContentType(cty string) BuilderOption {
	return func(b *Builder) { b.header.ContentType = cty }
}

// Builder is used to create a new token.
// Safe to use concurrently.
type Builder struct {
	signer    Signer
	header    Header
	headerRaw []byte
}

// NewBuilder returns new instance of Builder.
func NewBuilder(signer Signer, opts ...BuilderOption) *Builder {
	b := &Builder{
		signer: signer,
		header: Header{
			Algorithm: signer.Algorithm(),
			Type:      "JWT",
		},
	}

	for _, opt := range opts {
		opt(b)
	}

	b.headerRaw = encodeHeader(b.header)
	return b
}

// Build used to create and encode JWT with a provided claims.
// If claims param is of type []byte or string then it's treated as a marshaled JSON.
// In other words you can pass already marshaled claims.
func (b *Builder) Build(claims interface{}) (*Token, error) {
	rawClaims, err := encodeClaims(claims)
	if err != nil {
		return nil, err
	}

	lenH := len(b.headerRaw)
	lenC := b64EncodedLen(len(rawClaims))
	lenS := b64EncodedLen(b.signer.SignSize())

	token := make([]byte, lenH+1+lenC+1+lenS)
	idx := 0
	idx = copy(token[idx:], b.headerRaw)

	// add '.' and append encoded claims
	token[idx] = '.'
	idx++
	b64Encode(token[idx:], rawClaims)
	idx += lenC

	// calculate signature of already written 'header.claims'
	rawSignature, err := b.signer.Sign(token[:idx])
	if err != nil {
		return nil, err
	}

	// add '.' and append encoded signature
	token[idx] = '.'
	idx++
	b64Encode(token[idx:], rawSignature)

	t := &Token{
		raw:       token,
		dot1:      lenH,
		dot2:      lenH + 1 + lenC,
		header:    b.header,
		claims:    rawClaims,
		signature: rawSignature,
	}
	return t, nil
}

func encodeClaims(claims interface{}) ([]byte, error) {
	switch claims := claims.(type) {
	case []byte:
		return claims, nil
	case string:
		return []byte(claims), nil
	default:
		return json.Marshal(claims)
	}
}

func encodeHeader(header Header) []byte {
	if header.Type == "JWT" && header.ContentType == "" && header.KeyID == "" {
		if h := predefinedHeaders[header.Algorithm]; h != "" {
			return []byte(h)
		}
		// another algorithm? encode below
	}
	// returned err is always nil, see jwt.Header.MarshalJSON
	buf, _ := header.MarshalJSON()

	encoded := make([]byte, b64EncodedLen(len(buf)))
	b64Encode(encoded, buf)
	return encoded
}

func b64Encode(dst, src []byte) {
	base64.RawURLEncoding.Encode(dst, src)
}

func b64EncodedLen(n int) int {
	return base64.RawURLEncoding.EncodedLen(n)
}

var predefinedHeaders = map[Algorithm]string{
	EdDSA: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9",

	HS256: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
	HS384: "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9",
	HS512: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9",

	RS256: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
	RS384: "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9",
	RS512: "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9",

	ES256: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9",
	ES384: "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9",
	ES512: "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9",

	PS256: "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9",
	PS384: "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9",
	PS512: "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9",
}
