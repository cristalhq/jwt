package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
)

// Parse decodes a token and verifies it's signature.
func Parse(raw []byte, verifier Verifier) (*Token, error) {
	token, err := ParseNoVerify(raw)
	if err != nil {
		return nil, err
	}
	if err := verifier.Verify(token); err != nil {
		return nil, err
	}
	return token, nil
}

// ParseClaims decodes a token claims and verifies it's signature.
func ParseClaims(raw []byte, verifier Verifier, claims interface{}) error {
	token, err := Parse(raw, verifier)
	if err != nil {
		return err
	}
	return token.DecodeClaims(claims)
}

// ParseNoVerify decodes a token from a raw bytes.
// NOTE: Consider to use Parse with a verifier to verify token signature.
func ParseNoVerify(raw []byte) (*Token, error) {
	return parse(raw)
}

func parse(token []byte) (*Token, error) {
	// "eyJ" is `{"` which is begin of every JWT token.
	// Quick check for the invalid input.
	if !bytes.HasPrefix(token, []byte("eyJ")) {
		return nil, ErrInvalidFormat
	}

	dot1 := bytes.IndexByte(token, '.')
	dot2 := bytes.LastIndexByte(token, '.')
	if dot2 <= dot1 {
		return nil, ErrInvalidFormat
	}

	buf := make([]byte, len(token))

	headerN, err := b64Decode(buf, token[:dot1])
	if err != nil {
		return nil, ErrInvalidFormat
	}
	var header Header
	if err := json.Unmarshal(buf[:headerN], &header); err != nil {
		return nil, ErrInvalidFormat
	}

	claimsN, err := b64Decode(buf[headerN:], token[dot1+1:dot2])
	if err != nil {
		return nil, ErrInvalidFormat
	}
	claims := buf[headerN : headerN+claimsN]

	signN, err := b64Decode(buf[headerN+claimsN:], token[dot2+1:])
	if err != nil {
		return nil, ErrInvalidFormat
	}
	signature := buf[headerN+claimsN : headerN+claimsN+signN]

	tk := &Token{
		raw:       token,
		dot1:      dot1,
		dot2:      dot2,
		signature: signature,
		header:    header,
		claims:    claims,
	}
	return tk, nil
}

var b64Decode = base64.RawURLEncoding.Decode
