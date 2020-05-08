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

	payload, raw, signature, err := sign(b.signer, jsonClaims, jsonHeader)
	if err != nil {
		return nil, err
	}

	token := &Token{
		raw:       raw,
		payload:   payload,
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

func sign(signer Signer, jsonClaims, jsonHeader []byte) (payload, signed, signature []byte, err error) {

	//payload := make([]byte, 0, 64)

	lh := base64EncodedLen(len(jsonHeader))
	lc := base64EncodedLen(len(jsonClaims))
	ls := base64EncodedLen(signer.SignatureSize())

	pp := make([]byte, lc+lh+ls+2)

	base64Encode(pp[:lh], jsonHeader)
	pp[lh] = '.'
	base64Encode(pp[lh+1:lc+lh+2], jsonClaims)
	pp[lc+lh+1] = '.'

	signature, err = signer.Sign(pp[:lc+lh+1])
	if err != nil {
		return nil, nil, nil, err
	}

	base64Encode(pp[lc+lh+2:], signature)

	return pp[:lc+lh+1], pp, signature, nil
}

func concatParts(a, b []byte) []byte {
	buf := make([]byte, len(a)+1+len(b))
	buf[len(a)] = '.'

	copy(buf[:len(a)], a)
	copy(buf[len(a)+1:], b)

	return buf
}
