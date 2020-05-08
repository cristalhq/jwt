package jwt

import (
	"encoding/base64"
	"encoding/json"
)

const delimiter = '.'

var (
	base64Encode     = base64.RawURLEncoding.Encode
	base64EncodedLen = base64.RawURLEncoding.EncodedLen
)

// Builder is used to create a new token.
type Builder struct {
	signer Signer
	header Header
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
	jsonClaims, err := encodeClaims(claims)
	if err != nil {
		return nil, err
	}

	jsonHeader := encodeHeader(&b.header)

	headerLen := base64EncodedLen(len(jsonHeader))
	claimsLen := base64EncodedLen(len(jsonClaims))
	singatureLen := base64EncodedLen(b.signer.SignatureSize())

	payload := make([]byte, claimsLen+headerLen+singatureLen+2)

	delimiterIdx := claimsLen + headerLen + 1
	payload[headerLen] = delimiter
	payload[delimiterIdx] = delimiter

	base64Encode(payload[:headerLen], jsonHeader)
	base64Encode(payload[headerLen+1:delimiterIdx+1], jsonClaims)

	signature, err := sign(b.signer, payload, delimiterIdx)
	if err != nil {
		return nil, err
	}

	token := &Token{
		raw:       payload,
		payload:   payload[:delimiterIdx],
		signature: signature,
		header:    b.header,
		claims:    jsonClaims,
	}
	return token, nil
}

func encodeClaims(claims interface{}) (raw []byte, err error) {
	raw, err = json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	return raw, nil
}

func encodeHeader(header *Header) []byte {
	// returned err is always nil, see *Header.MarshalJSON
	buf, _ := header.MarshalJSON()

	return buf
}

func sign(signer Signer, payload []byte, delimiter int) (signature []byte, err error) {

	signature, err = signer.Sign(payload[:delimiter])
	if err != nil {
		return nil, err
	}

	base64Encode(payload[delimiter+1:], signature)

	return signature, nil
}
