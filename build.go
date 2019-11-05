package jwt

import (
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

// BinaryMarshaler a marshaling interface for user claims.
type BinaryMarshaler interface {
	MarshalBinary() (data []byte, err error)
}

// BuildBytes is used to create and encode JWT with a provided claims.
func BuildBytes(signer Signer, claims BinaryMarshaler) ([]byte, error) {
	return NewTokenBuilder(signer).BuildBytes(claims)
}

// Build is used to create and encode JWT with a provided claims.
func Build(signer Signer, claims BinaryMarshaler) (*Token, error) {
	return NewTokenBuilder(signer).Build(claims)
}

// BuildWithHeader is used to create and encode JWT with a provided claims.
func BuildWithHeader(signer Signer, header Header, claims BinaryMarshaler) (*Token, error) {
	b := &TokenBuilder{
		signer: signer,
		header: header,
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

// BuildBytes used to create and encode JWT with a provided claims.
func (b *TokenBuilder) BuildBytes(claims BinaryMarshaler) ([]byte, error) {
	token, err := b.Build(claims)
	if err != nil {
		return nil, err
	}
	return token.Raw(), nil
}

// Build used to create and encode JWT with a provided claims.
func (b *TokenBuilder) Build(claims BinaryMarshaler) (*Token, error) {
	rawClaims, encodedClaims, err := encodeClaims(claims)
	if err != nil {
		return nil, err
	}

	encodedHeader := encodeHeader(&b.header)
	payload := concatParts(encodedHeader, encodedClaims)

	signed, signature, err := signPayload(b.signer, payload)
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

func encodeHeader(header *Header) []byte {
	if header.Type == "JWT" {
		switch header.Algorithm {
		case NoEncryption:
			return []byte("eyJhbGciOiJub25lIn0")
		case EdDSA:
			return []byte("eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9")

		case HS256:
			return []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
		case HS384:
			return []byte("eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9")
		case HS512:
			return []byte("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9")

		case RS256:
			return []byte("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9")
		case RS384:
			return []byte("eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9")
		case RS512:
			return []byte("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9")

		case ES256:
			return []byte("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9")
		case ES384:
			return []byte("eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9")
		case ES512:
			return []byte("eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9")

		case PS256:
			return []byte("eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9")
		case PS384:
			return []byte("eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9")
		case PS512:
			return []byte("eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9")

		default:
			// another algorithm? encode below
		}
	}

	// returned err is always nil, see *Header.MarshalJSON
	buf, _ := json.Marshal(header)

	encoded := make([]byte, base64EncodedLen(len(buf)))
	base64Encode(encoded, buf)

	return encoded
}

func encodeClaims(claims BinaryMarshaler) (raw, encoded []byte, err error) {
	raw, err = claims.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	encoded = make([]byte, base64EncodedLen(len(raw)))
	base64Encode(encoded, raw)

	return raw, encoded, nil
}

func signPayload(signer Signer, payload []byte) (signed, signature []byte, err error) {
	signature, err = signer.Sign(payload)
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
