package jwt

import (
	"encoding/base64"
	"encoding/json"
)

var (
	base64Encode     = base64.RawURLEncoding.Encode
	base64EncodedLen = base64.RawURLEncoding.EncodedLen
)

// Builder is used to create a new token.
type Builder struct {
	signer    Signer
	header    Header
	headerRaw string
}

// BuildBytes is used to create and encode JWT with a provided claims.
func BuildBytes(signer Signer, claims interface{}) ([]byte, error) {
	return NewBuilder(signer).BuildBytes(claims)
}

// Build is used to create and encode JWT with a provided claims.
func Build(signer Signer, claims interface{}) (*Token, error) {
	return NewBuilder(signer).Build(claims)
}

// NewBuilder returns new instance of Builder.
func NewBuilder(signer Signer) *Builder {
	b := &Builder{
		signer: signer,
		header: Header{
			Algorithm: signer.Algorithm(),
			Type:      "JWT",
		},
	}
	b.headerRaw = encodeHeaderPrec(&b.header)
	return b
}

// BuildBytes used to create and encode JWT with a provided claims.
func (b *Builder) BuildBytes(claims interface{}) ([]byte, error) {
	token, err := b.Build(claims)
	if err != nil {
		return nil, err
	}
	return token.Raw(), nil
}

// Build used to create and encode JWT with a provided claims.
func (b *Builder) Build(claims interface{}) (*Token, error) {
	rawClaims, err := encodeClaims(claims)
	if err != nil {
		return nil, err
	}

	lenH := len(b.headerRaw)
	lenP := base64EncodedLen(len(rawClaims))
	lenS := 500
	raw := make([]byte, lenH+1+lenP+1+lenS)

	idx := 0
	idx += copy(raw[idx:], b.headerRaw)
	idx += copy(raw[idx:], ".")

	base64Encode(raw[idx:], rawClaims)
	idx += base64EncodedLen(len(rawClaims))

	signature, err := b.signer.Sign(raw[:idx])
	if err != nil {
		return nil, err
	}

	idx += copy(raw[idx:], ".")
	base64Encode(raw[idx:], signature)
	idx += base64EncodedLen(len(signature))

	raw = raw[:idx]

	token := &Token{
		raw:       raw,
		payload:   raw[:lenH+1+lenP],
		signature: signature,
		header:    b.header,
		claims:    rawClaims,
	}
	return token, nil
}

func encodeClaims(claims interface{}) ([]byte, error) {
	switch claims := claims.(type) {
	case []byte:
		return claims, nil
	default:
		return json.Marshal(claims)
	}
}

func encodeHeaderPrec(header *Header) string {
	if header.Type == "JWT" && header.ContentType == "" {
		switch header.Algorithm {
		case EdDSA:
			return encHeaderEdDSA

		case HS256:
			return encHeaderHS256
		case HS384:
			return encHeaderHS384
		case HS512:
			return encHeaderHS512

		case RS256:
			return encHeaderRS256
		case RS384:
			return encHeaderRS384
		case RS512:
			return encHeaderRS512

		case ES256:
			return encHeaderES256
		case ES384:
			return encHeaderES384
		case ES512:
			return encHeaderES512

		case PS256:
			return encHeaderPS256
		case PS384:
			return encHeaderPS384
		case PS512:
			return encHeaderPS512

		default:
			// another algorithm? encode below
		}
	}
	// returned err is always nil, see *Header.MarshalJSON
	buf, _ := json.Marshal(header)

	encoded := make([]byte, base64EncodedLen(len(buf)))
	base64Encode(encoded, buf)
	return string(encoded)
}

var (
	encHeaderEdDSA = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9"

	encHeaderHS256 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	encHeaderHS384 = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9"
	encHeaderHS512 = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9"

	encHeaderRS256 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	encHeaderRS384 = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9"
	encHeaderRS512 = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9"

	encHeaderES256 = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9"
	encHeaderES384 = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9"
	encHeaderES512 = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9"

	encHeaderPS256 = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9"
	encHeaderPS384 = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9"
	encHeaderPS512 = "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9"
)
