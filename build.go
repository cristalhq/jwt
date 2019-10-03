package jwt

import (
	"encoding"
	"encoding/base64"
	"encoding/json"
)

const tokenSep = '.'

var (
	base64Encode     = base64.RawURLEncoding.Encode
	base64EncodedLen = base64.RawURLEncoding.EncodedLen
)

// TokenBuilder is used to create a new token.
type TokenBuilder struct {
	signer Signer
	header Header
}

// Build is used to create and encode JWT with a provided claims.
func Build(signer Signer, claims encoding.BinaryMarshaler) (*Token, error) {
	return NewTokenBuilder(signer).Build(claims)
}

// BuildWithHeader is used to create and encode JWT with a provided claims.
func BuildWithHeader(signer Signer, header *Header, claims encoding.BinaryMarshaler) (*Token, error) {
	b := &TokenBuilder{
		signer: signer,
		header: *header,
	}
	return b.Build(claims)
}

// NewTokenBuilder returns new instance of TokenBuilder.
func NewTokenBuilder(signer Signer) *TokenBuilder {
	b := &TokenBuilder{
		signer: signer,

		header: Header{
			Type:      "JWT",
			Algorithm: signer.Algorithm(),
		},
	}
	return b
}

// Build used to create and encode JWT with a provided claims.
func (b *TokenBuilder) Build(claims encoding.BinaryMarshaler) (*Token, error) {
	encodedHeader, err := b.encodeHeader()
	if err != nil {
		return nil, err
	}

	rawClaims, encodedClaims, err := b.encodeClaims(claims)
	if err != nil {
		return nil, err
	}

	payload := concatParts(encodedHeader, encodedClaims)

	signed, signature, err := b.signPayload(payload)
	if err != nil {
		return nil, err
	}

	token := &Token{
		raw:       signed,
		header:    b.header,
		claims:    rawClaims,
		payload:   payload,
		signature: signature,
	}
	return token, nil
}

func (b *TokenBuilder) encodeHeader() ([]byte, error) {
	switch b.signer.Algorithm() {
	case NoEncryption:
		return []byte("eyJhbGciOiJub25lIn0"), nil

	case HS256:
		return []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"), nil
	case HS384:
		return []byte("eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9"), nil
	case HS512:
		return []byte("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9"), nil

	case RS256:
		return []byte("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"), nil
	case RS384:
		return []byte("eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9"), nil
	case RS512:
		return []byte("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9"), nil

	case ES256:
		return []byte("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9"), nil
	case ES384:
		return []byte("eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9"), nil
	case ES512:
		return []byte("eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9"), nil

	case PS256:
		return []byte("eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9"), nil
	case PS384:
		return []byte("eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9"), nil
	case PS512:
		return []byte("eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9"), nil

	default:
		// another algorithm? encode below
	}

	buf, err := json.Marshal(b.header)
	if err != nil {
		return nil, err
	}

	encoded := make([]byte, base64EncodedLen(len(buf)))
	base64Encode(encoded, buf)

	return encoded, nil
}

func (b *TokenBuilder) encodeClaims(claims encoding.BinaryMarshaler) (raw, encoded []byte, err error) {
	raw, err = claims.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	encoded = make([]byte, base64EncodedLen(len(raw)))
	base64Encode(encoded, raw)

	return raw, encoded, nil
}

func (b *TokenBuilder) signPayload(payload []byte) (signed, signature []byte, err error) {
	signature, err = b.signer.Sign(payload)
	if err != nil {
		return nil, nil, err
	}

	encodedSignature := make([]byte, base64EncodedLen(len(signature)))
	base64Encode(encodedSignature, signature)

	signed = concatParts(payload, encodedSignature)

	return signed, signature, nil
}

func concatParts(a, b []byte) []byte {
	buf := make([]byte, len(a)+1+len(b))
	buf[len(a)] = tokenSep

	copy(buf[:len(a)], a)
	copy(buf[len(a)+1:], b)

	return buf
}
