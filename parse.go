package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
)

var base64Decode = base64.RawURLEncoding.Decode

// ParseString decodes a token.
func ParseString(raw string) (*Token, error) {
	return Parse([]byte(raw))
}

// Parse decodes a token from a raw bytes.
func Parse(raw []byte) (*Token, error) {
	dot1 := bytes.IndexByte(raw, '.')
	dot2 := bytes.LastIndexByte(raw, '.')
	if dot2 <= dot1 {
		return nil, ErrInvalidFormat
	}

	buf := make([]byte, len(raw))

	headerN, err := base64Decode(buf, raw[:dot1])
	if err != nil {
		return nil, err
	}

	claimsN, err := base64Decode(buf[headerN:], raw[dot1+1:dot2])
	if err != nil {
		return nil, err
	}
	claims := buf[headerN : headerN+claimsN]

	signN, err := base64Decode(buf[headerN+claimsN:], raw[dot2+1:])
	if err != nil {
		return nil, err
	}
	signature := buf[headerN+claimsN : headerN+claimsN+signN]

	var header Header
	if err := json.Unmarshal(buf[:headerN], &header); err != nil {
		return nil, err
	}

	token := &Token{
		raw:       raw,
		header:    header,
		claims:    claims,
		payload:   raw[:dot2],
		signature: signature,
	}
	return token, nil
}

// ParseAndVerifyString decodes a token and verifies it's signature with a given signer.
func ParseAndVerifyString(raw string, signer Signer) (*Token, error) {
	return ParseAndVerify([]byte(raw), signer)
}

// ParseAndVerify decodes a token and verifies it's signature with a given signer.
func ParseAndVerify(raw []byte, signer Signer) (*Token, error) {
	token, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if err := signer.Verify(token.payload, token.signature); err != nil {
		return nil, err
	}
	return token, nil
}
