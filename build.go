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

	signsize := 500
	raww := make([]byte, len(b.headerRaw)+1+base64EncodedLen(len(rawClaims))+1+signsize)
	idx := 0
	idx += copy(raww[idx:], b.headerRaw)
	idx += copy(raww[idx:], ".")

	//idx += copy(raww[idx:], encodedClaims)
	base64Encode(raww[idx:], rawClaims)
	idx += base64EncodedLen(len(rawClaims))

	signature, err := b.signer.Sign(raww[:idx])
	if err != nil {
		return nil, err
	}
	//encodedSignature := make([]byte, base64EncodedLen(len(signature)))
	idx += copy(raww[idx:], ".")
	base64Encode(raww[idx:], signature)
	idx += base64EncodedLen(len(signature))
	//base64Encode(encodedSignature, signature)

	//idx += copy(raww[idx:], encodedSignature)

	//signed = concatParts(payload, encodedSignature)
	//raww = append(raww, b.headerRaw...)
	//raww = append(raww, '.')
	//raww = append(raww, encodedClaims...)
	//raww = append(raww, '.')
	//payload := concatParts([]byte(b.headerRaw), encodedClaims)
	//raw, signature, err := signPayload(b.signer, raww[:len(b.headerRaw)+1+len(encodedClaims)])
	//if err != nil {
	//	return nil, err
	//}
	//signs := base64EncodedLen(len(signature))
	//tmp := make([]byte, signs)
	//base64Encode(tmp, signature)
	//raww = append(raww, tmp...)
	raw := raww[:idx]

	token := &Token{
		raw:       raw,
		payload:   raw[:len(b.headerRaw)+1+base64EncodedLen(len(rawClaims))],
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

//
//func encodeHeader(header *Header) []byte {
//	// returned err is always nil, see *Header.MarshalJSON
//	buf, _ := header.MarshalJSON()
//
//	encoded := make([]byte, base64EncodedLen(len(buf)))
//	base64Encode(encoded, buf)
//
//	return encoded
//}

//func signPayload(signer Signer, payload []byte) (signed, signature []byte, err error) {
//	signature, err = signer.Sign(payload)
//	if err != nil {
//		return nil, nil, err
//	}
//
//	encodedSignature := make([]byte, base64EncodedLen(len(signature)))
//	base64Encode(encodedSignature, signature)
//	signed = concatParts(payload, encodedSignature)
//
//	return signed, signature, nil
//}

//func concatParts(a, b []byte) []byte {
//	buf := make([]byte, len(a)+1+len(b))
//	buf[len(a)] = '.'
//
//	copy(buf[:len(a)], a)
//	copy(buf[len(a)+1:], b)
//
//	return buf
//}

func encodeHeaderPrec(header *Header) string {
	if header.Type == "JWT" && header.ContentType == "" {
		switch header.Algorithm {
		case EdDSA:
			return ("eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9")

		case HS256:
			return ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
		case HS384:
			return ("eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9")
		case HS512:
			return ("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9")

		case RS256:
			return ("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9")
		case RS384:
			return ("eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9")
		case RS512:
			return ("eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9")

		case ES256:
			return ("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9")
		case ES384:
			return ("eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9")
		case ES512:
			return ("eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9")

		case PS256:
			return ("eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9")
		case PS384:
			return ("eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9")
		case PS512:
			return ("eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9")

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
