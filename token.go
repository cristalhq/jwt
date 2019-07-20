package jwt

import "encoding/json"

// Token represents a JWT token.
type Token struct {
	raw    []byte
	header Header
	claims json.RawMessage
}

// Raw returns token's raw bytes.
func (t *Token) Raw() []byte {
	return t.raw
}

// Header returns token's header.
func (t *Token) Header() Header {
	return t.header
}
