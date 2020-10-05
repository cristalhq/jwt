package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
)

// ParseString decodes a token and verifies it's signature.
func ParseString(token string, verifier Verifier) (*Token, error) {
	return Parse([]byte(token), verifier)
}

// Parse decodes a token from bytes and verifies it's signature.
func Parse(token []byte, verifier Verifier) (*Token, error) {
	tok, errParse := parse(token)
	if errParse != nil {
		return nil, errParse
	}

	got := tok.Header().Algorithm
	want := verifier.Algorithm()
	if !constTimeEqual(got.String(), want.String()) {
		return nil, ErrAlgorithmMismatch
	}

	errVerify := verifier.Verify(tok.Payload(), tok.Signature())
	if errVerify != nil {
		return nil, errVerify
	}
	return tok, nil
}

// ParseNoVerifyString decodes a token without signature verification.
func ParseNoVerifyString(token string) (*Token, error) {
	return ParseNoVerify([]byte(token))
}

// ParseNoVerify decodes a token without signature verification.
func ParseNoVerify(token []byte) (*Token, error) {
	return parse(token)
}

func parse(token []byte) (*Token, error) {
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

	tok := &Token{
		raw:       token,
		dot1:      dot1,
		dot2:      dot2,
		header:    header,
		claims:    claims,
		signature: signature,
	}
	return tok, nil
}

var b64Decode = base64.RawURLEncoding.Decode
