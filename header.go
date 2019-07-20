package jwt

// Header stores JWT header data.
type Header struct {
	Type      string    `json:"typ"`
	Algorithm Algorithm `json:"alg"`
}
