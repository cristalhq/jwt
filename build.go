package jwt

import (
	"encoding"
	"encoding/base64"
	"encoding/json"
)

var (
	base64Encode     = base64.RawURLEncoding.Encode
	base64EncodedLen = base64.RawURLEncoding.EncodedLen
)

// TokenBuilder is used to create a new token.
type TokenBuilder struct {
	signer Signer
	key    interface{}
	header Header
}

// NewTokenBuilder returns new instance of TokenBuilder.
func NewTokenBuilder(signer Signer, key interface{}) *TokenBuilder {
	b := &TokenBuilder{
		signer: signer,
		key:    key,

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

	payload := b.encodePayload(encodedHeader, encodedClaims)

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

func (b *TokenBuilder) encodePayload(headers, claims []byte) []byte {
	return concat3(headers, []byte{'.'}, claims)
}

func (b *TokenBuilder) signPayload(payload []byte) (signed, signature []byte, err error) {
	signature, err = b.signer.Sign(payload, b.key)
	if err != nil {
		return nil, nil, err
	}

	encodedSignature := make([]byte, base64EncodedLen(len(signature)))
	base64Encode(encodedSignature, signature)

	signed = concat3(payload, []byte{'.'}, encodedSignature)

	return signed, signature, nil
}

func concat3(a, b, c []byte) []byte {
	return append(a, append(b, c...)...)
}
