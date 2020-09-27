package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
)

// ParseString decodes a token.
func ParseString(token string, verifier Verifier) (*Token, error) {
	return Parse([]byte(token), verifier)
}

// Parse decodes a token from a raw bytes.
func Parse(token []byte, verifier Verifier) (*Token, error) {
	tok, errParse := parse(token)
	if errParse != nil {
		return nil, errParse
	}

	gotAlg := tok.Header().Algorithm.String()
	wantAlg := verifier.Algorithm().String()
	if !constTimeEqual(gotAlg, wantAlg) {
		return nil, ErrAlgorithmMismatch
	}

	errVerify := verifier.Verify(tok.PayloadPart(), tok.Signature())
	if errVerify != nil {
		return nil, errVerify
	}
	return tok, nil
}

// ParseNoVerifyString decodes a token and verifies it's signature.
func ParseNoVerifyString(token string) (*Token, error) {
	return ParseNoVerify([]byte(token))
}

// ParseNoVerify decodes a token and verifies it's signature.
func ParseNoVerify(token []byte) (*Token, error) {
	tok, err := parse(token)
	if err != nil {
		return nil, err
	}
	return tok, nil
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
		return nil, ErrInvalidHeaderFormat
	}
	var header Header
	if err := json.Unmarshal(buf[:headerN], &header); err != nil {
		return nil, ErrInvalidHeaderFormat
	}

	claimsN, err := b64Decode(buf[headerN:], token[dot1+1:dot2])
	if err != nil {
		return nil, ErrInvalidClaimsFormat
	}
	claims := buf[headerN : headerN+claimsN]

	signN, err := b64Decode(buf[headerN+claimsN:], token[dot2+1:])
	if err != nil {
		return nil, ErrInvalidSignatureFormat
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
