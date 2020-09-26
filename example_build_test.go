package jwt_test

import (
	"fmt"

	"github.com/cristalhq/jwt/v3"
)

func ExampleBuilder_Build() {
	key := []byte(`secret`)
	signer, _ := jwt.NewSignerHS(jwt.HS256, key)
	builder := jwt.NewBuilder(signer)

	claims := &jwt.RegisteredClaims{
		Audience: []string{"admin"},
		ID:       "random-unique-string",
	}
	token, err := builder.Build(claims)
	checkErr(err)

	fmt.Printf("Algorithm %v\n", token.Header().Algorithm)
	fmt.Printf("Type      %v\n", token.Header().Type)
	fmt.Printf("Claims    %v\n", string(token.Claims()))
	fmt.Printf("Payload   %v\n", string(token.PayloadPart()))
	fmt.Printf("Token     %v\n", string(token.Bytes()))

	// Output:
	// Algorithm HS256
	// Type      JWT
	// Claims    {"jti":"random-unique-string","aud":"admin"}
	// Payload   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJyYW5kb20tdW5pcXVlLXN0cmluZyIsImF1ZCI6ImFkbWluIn0
	// Token     eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJyYW5kb20tdW5pcXVlLXN0cmluZyIsImF1ZCI6ImFkbWluIn0.uNaqGEggmy02lZq8FM7KoUKXhOy-zrSF7inYuzIET9o
}

type userClaims struct {
	jwt.RegisteredClaims
	IsAdministrator bool   `json:"is_admin"`
	Email           string `json:"email"`
}

func ExampleBuilder2() {
	key := []byte(`secret`)
	signer, _ := jwt.NewSignerHS(jwt.HS256, key)
	builder := jwt.NewBuilder(signer)

	claims := &userClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: []string{"admin"},
			ID:       "random-unique-string",
		},
		IsAdministrator: true,
		Email:           "foo@bar.baz",
	}
	token, err := builder.Build(claims)
	checkErr(err)

	fmt.Printf("Claims    %v\n", string(token.Claims()))
	fmt.Printf("Payload   %v\n", string(token.PayloadPart()))
	fmt.Printf("Token     %v\n", string(token.Bytes()))

	// Output:
	// Claims    {"jti":"random-unique-string","aud":"admin","is_admin":true,"email":"foo@bar.baz"}
	// Payload   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJyYW5kb20tdW5pcXVlLXN0cmluZyIsImF1ZCI6ImFkbWluIiwiaXNfYWRtaW4iOnRydWUsImVtYWlsIjoiZm9vQGJhci5iYXoifQ
	// Token     eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJyYW5kb20tdW5pcXVlLXN0cmluZyIsImF1ZCI6ImFkbWluIiwiaXNfYWRtaW4iOnRydWUsImVtYWlsIjoiZm9vQGJhci5iYXoifQ.oKE62_k3bqAlKwdBJDBJq5DQ_0FvpNv6e1u6hF_ShQs
}

type dummyClaims map[string]interface{}

func ExampleBuilder() {
	key := []byte(`secret`)
	signer, _ := jwt.NewSignerHS(jwt.HS256, key)
	builder := jwt.NewBuilder(signer)

	claims := dummyClaims(map[string]interface{}{
		"aUdIeNcE": "@everyone",
		"well":     "well-well-well",
	})
	token, err := builder.Build(&claims)
	checkErr(err)

	fmt.Printf("Claims    %v\n", string(token.Claims()))
	fmt.Printf("Payload   %v\n", string(token.PayloadPart()))
	fmt.Printf("Token     %v\n", string(token.Bytes()))

	// Output:
	// Claims    {"aUdIeNcE":"@everyone","well":"well-well-well"}
	// Payload   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhVWRJZU5jRSI6IkBldmVyeW9uZSIsIndlbGwiOiJ3ZWxsLXdlbGwtd2VsbCJ9
	// Token     eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhVWRJZU5jRSI6IkBldmVyeW9uZSIsIndlbGwiOiJ3ZWxsLXdlbGwtd2VsbCJ9.vN4rxWHBX4mjG-s0tiM_9ngX_e8KOEyXyEdjsTiTvqI
}
