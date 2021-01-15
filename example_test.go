package jwt_test

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/cristalhq/jwt/v3"
)

func Example() {
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
	newToken, err := builder.Build(claims)
	checkErr(err)

	// here is token as byte slice
	var _ []byte = newToken.Raw() // or just token.String() for string

	// create a Verifier (HMAC in this example)
	verifier, err := jwt.NewVerifierHS(jwt.HS256, key)
	checkErr(err)

	// parse a Token (by example received from a request)
	tokenStr := newToken.String()
	token, err := jwt.ParseAndVerifyString(tokenStr, verifier)
	checkErr(err)

	// and verify it's signature
	err = verifier.Verify(token.Payload(), token.Signature())
	checkErr(err)

	// also you can parse and verify together
	newToken, err = jwt.ParseAndVerifyString(tokenStr, verifier)
	checkErr(err)

	// get standard claims
	var newClaims jwt.StandardClaims
	errClaims := json.Unmarshal(newToken.RawClaims(), &newClaims)
	checkErr(errClaims)

	// verify claims as you
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

	fmt.Printf("Algorithm %v\n", token.Header().Algorithm)
	fmt.Printf("Type      %v\n", token.Header().Type)
	fmt.Printf("Claims    %v\n", string(token.RawClaims()))
	fmt.Printf("Payload   %v\n", string(token.Payload()))
	fmt.Printf("Token     %v\n", string(token.Raw()))

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

	fmt.Printf("Claims    %v\n", string(token.RawClaims()))
	fmt.Printf("Payload   %v\n", string(token.Payload()))
	fmt.Printf("Token     %v\n", string(token.Raw()))

	// Output:
	// Claims    {"jti":"random-unique-string","aud":"admin","is_admin":true,"email":"foo@bar.baz"}
	// Payload   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJyYW5kb20tdW5pcXVlLXN0cmluZyIsImF1ZCI6ImFkbWluIiwiaXNfYWRtaW4iOnRydWUsImVtYWlsIjoiZm9vQGJhci5iYXoifQ
	// Token     eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJyYW5kb20tdW5pcXVlLXN0cmluZyIsImF1ZCI6ImFkbWluIiwiaXNfYWRtaW4iOnRydWUsImVtYWlsIjoiZm9vQGJhci5iYXoifQ.oKE62_k3bqAlKwdBJDBJq5DQ_0FvpNv6e1u6hF_ShQs
}

func ExampleParse() {
	rawToken := []byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIn0.dv9-XpY9P8ypm1uWQwB6eKvq3jeyodLA7brhjsf4JVs`)

	token, err := jwt.Parse(rawToken)
	checkErr(err)

	fmt.Printf("Algorithm %v\n", token.Header().Algorithm)
	fmt.Printf("Type      %v\n", token.Header().Type)
	fmt.Printf("Claims    %v\n", string(token.RawClaims()))
	fmt.Printf("Payload   %v\n", string(token.Payload()))
	fmt.Printf("Token     %v\n", string(token.Raw()))

	// Output:
	// Algorithm HS256
	// Type      JWT
	// Claims    {"aud":"admin","jti":"random-unique-string"}
	// Payload   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIn0
	// Token     eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIn0.dv9-XpY9P8ypm1uWQwB6eKvq3jeyodLA7brhjsf4JVs
}

func ExampleParseAndVerify() {
	rawToken := []byte(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIn0.dv9-XpY9P8ypm1uWQwB6eKvq3jeyodLA7brhjsf4JVs`)

	key := []byte(`secret`)
	verifier, _ := jwt.NewVerifierHS(jwt.HS256, key)

	token, err := jwt.ParseAndVerify(rawToken, verifier)
	checkErr(err)

	fmt.Printf("Algorithm %v\n", token.Header().Algorithm)
	fmt.Printf("Type      %v\n", token.Header().Type)
	fmt.Printf("Claims    %v\n", string(token.RawClaims()))
	fmt.Printf("Payload   %v\n", string(token.Payload()))
	fmt.Printf("Token     %v\n", string(token.Raw()))

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
