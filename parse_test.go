package jwt

import (
	"testing"
)

func TestParseAndVerifyString(t *testing.T) {
	sign, _ := NewHS256([]byte(`test-key-256`))
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWRpZW5jZSIsImp0aSI6Imp1c3QgYW4gaWQifQ.6EWV4IFTyCqCUn-_R1AFRgJptvmV09Os57WAejPcf7Q"

	if _, err := ParseAndVerifyString(token, sign); err != nil {
		t.Fatal(err)
	}
}
