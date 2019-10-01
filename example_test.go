package jwt

import (
	"github.com/cristalhq/jwt"
)

func simpleExample() []byte {
	signer := jwt.NewHS256([]byte(`secret`))
	builder := jwt.NewTokenBuilder(signer)

	claims := &jwt.StandardClaims{
		Audience: []string{"admin"},
		ID:       "random-unique-string",
	}
	token, _ := builder.Build(claims)

	return token.Raw() // JWT signed token
}
