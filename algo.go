package jwt

// Algorithm represents algorithms for signing and verifying.
type Algorithm string

// Algorithm names for signing and verifying.
const (
	HS256 Algorithm = "HS256"
	HS384 Algorithm = "HS384"
	HS512 Algorithm = "HS512"
)
