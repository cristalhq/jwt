package jwt

import (
	"testing"
)

// How to run: `go test -fuzz=FuzzParseNoVerify -parallel=32`
func FuzzParseNoVerify(f *testing.F) {
	f.Add([]byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1MDUxODI5Mzg2ODc2NTc3MTIzIiwibmFtZSI6IjdNZUNSbG9xSXAiLCJpYXQiOjE3MjA1NTM4NDV9.QW7kzr70jrbZpPV4"))
	f.Add([]byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"))
	f.Add([]byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid_signature"))
	f.Add([]byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"))
	f.Add([]byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30."))
	f.Add([]byte(""))
	f.Add([]byte("random bytes"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := ParseNoVerify(data); err != nil {
			t.Skip()
		}
	})
}
