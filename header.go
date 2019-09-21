package jwt

// Header stores JWT header data.
// see https://tools.ietf.org/html/rfc7515
// and https://tools.ietf.org/html/rfc7519
type Header struct {
	Algorithm      Algorithm `json:"alg"`
	Type           string    `json:"typ,omitempty"` // type of JWS: it can only be "JWT" here
	ContentType    string    `json:"cty,omitempty"`
	JSONKeyURL     string    `json:"jku,omitempty"`
	KeyID          string    `json:"kid,omitempty"`
	X509URL        string    `json:"x5u,omitempty"`
	X509Thumbprint string    `json:"x5t,omitempty"`
}
