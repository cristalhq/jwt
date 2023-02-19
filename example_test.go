package jwt_test

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/cristalhq/jwt/v5"
)

func ExampleSignAndVerify() {
	// create a Signer (HMAC in this example)
	key := []byte(`secret`)
	signer, err := jwt.NewSignerHS(jwt.HS256, key)
	checkErr(err)

	// create claims (you can create your own, see: Example_BuildUserClaims)
	claims := &jwt.RegisteredClaims{
		Audience: []string{"admin"},
		ID:       "random-unique-string",
	}

	// create a Builder
	builder := jwt.NewBuilder(signer)

	// and build a Token
	token, err := builder.Build(claims)
	checkErr(err)

	// here is token as a string
	var _ string = token.String()

	// create a Verifier (HMAC in this example)
	verifier, err := jwt.NewVerifierHS(jwt.HS256, key)
	checkErr(err)

	// parse and verify a token
	tokenBytes := token.Bytes()
	newToken, err := jwt.Parse(tokenBytes, verifier)
	checkErr(err)

	// or just verify it's signature
	err = verifier.Verify(newToken)
	checkErr(err)

	// also you can parse without verify (NOT RECOMMENDED!)
	newToken, err = jwt.ParseNoVerify(tokenBytes)
	checkErr(err)

	// get REGISTERED claims
	var newClaims jwt.RegisteredClaims
	errClaims := json.Unmarshal(newToken.Claims(), &newClaims)
	checkErr(errClaims)

	// or parse only claims
	errParseClaims := jwt.ParseClaims(tokenBytes, verifier, &newClaims)
	checkErr(errParseClaims)

	// verify claims as you wish
	var _ bool = newClaims.IsForAudience("admin")
	var _ bool = newClaims.IsValidAt(time.Now())

	// Output:
}

func ExampleBuild() {
	key := []byte(`secret`)
	signer, _ := jwt.NewSignerHS(jwt.HS256, key)
	builder := jwt.NewBuilder(signer)

	claims := &jwt.RegisteredClaims{
		Audience: []string{"admin"},
		ID:       "random-unique-string",
	}
	token, err := builder.Build(claims)
	checkErr(err)

	fmt.Printf("Token     %s\n", token.String())
	fmt.Printf("Algorithm %s\n", token.Header().Algorithm)
	fmt.Printf("Type      %s\n", token.Header().Type)
	fmt.Printf("Claims    %s\n", token.Claims())
	fmt.Printf("HeaderPart    %s\n", token.HeaderPart())
	fmt.Printf("ClaimsPart    %s\n", token.ClaimsPart())
	fmt.Printf("PayloadPart   %s\n", token.PayloadPart())
	fmt.Printf("SignaturePart %s\n", token.SignaturePart())

	// Output:
	// Token     eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJyYW5kb20tdW5pcXVlLXN0cmluZyIsImF1ZCI6ImFkbWluIn0.uNaqGEggmy02lZq8FM7KoUKXhOy-zrSF7inYuzIET9o
	// Algorithm HS256
	// Type      JWT
	// Claims    {"jti":"random-unique-string","aud":"admin"}
	// HeaderPart    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
	// ClaimsPart    eyJqdGkiOiJyYW5kb20tdW5pcXVlLXN0cmluZyIsImF1ZCI6ImFkbWluIn0
	// PayloadPart   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJyYW5kb20tdW5pcXVlLXN0cmluZyIsImF1ZCI6ImFkbWluIn0
	// SignaturePart uNaqGEggmy02lZq8FM7KoUKXhOy-zrSF7inYuzIET9o
}

// Payload   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJyYW5kb20tdW5pcXVlLXN0cmluZyIsImF1ZCI6ImFkbWluIn0

type userClaims struct {
	jwt.RegisteredClaims
	IsAdministrator bool   `json:"is_admin"`
	Email           string `json:"email"`
}

func ExampleBuild_WithUserClaims() {
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

func ExampleParse() {
	rawToken := []byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIn0.dv9-XpY9P8ypm1uWQwB6eKvq3jeyodLA7brhjsf4JVs`)

	key := []byte(`secret`)
	verifier, _ := jwt.NewVerifierHS(jwt.HS256, key)

	token, err := jwt.Parse(rawToken, verifier)
	checkErr(err)

	fmt.Printf("Algorithm %v\n", token.Header().Algorithm)
	fmt.Printf("Type      %v\n", token.Header().Type)
	fmt.Printf("Claims    %v\n", string(token.Claims()))
	fmt.Printf("Payload   %v\n", string(token.PayloadPart()))
	fmt.Printf("Token     %v\n", string(token.Bytes()))

	// Output:
	// Algorithm HS256
	// Type      JWT
	// Claims    {"aud":"admin","jti":"random-unique-string"}
	// Payload   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIn0
	// Token     eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIn0.dv9-XpY9P8ypm1uWQwB6eKvq3jeyodLA7brhjsf4JVs
}

func ExampleParseNoVerify() {
	rawToken := []byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIn0.dv9-XpY9P8ypm1uWQwB6eKvq3jeyodLA7brhjsf4JVs`)

	token, err := jwt.ParseNoVerify(rawToken)
	checkErr(err)

	fmt.Printf("Algorithm %v\n", token.Header().Algorithm)
	fmt.Printf("Type      %v\n", token.Header().Type)
	fmt.Printf("Claims    %v\n", string(token.Claims()))
	fmt.Printf("Payload   %v\n", string(token.PayloadPart()))
	fmt.Printf("Token     %v\n", string(token.Bytes()))

	// Output:
	// Algorithm HS256
	// Type      JWT
	// Claims    {"aud":"admin","jti":"random-unique-string"}
	// Payload   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIn0
	// Token     eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIn0.dv9-XpY9P8ypm1uWQwB6eKvq3jeyodLA7brhjsf4JVs
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
