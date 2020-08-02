package jwt_test

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/cristalhq/jwt/v3"
)

func Example_JWT() {
	// 1. create a signer & a verifier
	key := []byte(`secret`)
	signer, err := jwt.NewSignerHS(jwt.HS256, key)
	checkErr(err)
	verifier, err := jwt.NewVerifierHS(jwt.HS256, key)
	checkErr(err)

	// 2. create q standard claims
	// (you can create your own, see: Example_BuildUserClaims)
	claims := &jwt.StandardClaims{
		Audience: []string{"admin"},
		ID:       "random-unique-string",
	}

	// 3. create a builder
	builder := jwt.NewBuilder(signer)

	// 4. and build a token
	token, errBuild := builder.Build(claims)
	checkErr(errBuild)

	// 5. here is your token  :)
	var _ []byte = token.Raw() // or just token.String() for string

	// 6. parse a token (by example received from a request)
	tokenStr := token.String()
	newToken, errParse := jwt.ParseString(tokenStr)
	checkErr(errParse)

	// 7. and verify it's signature
	errVerify := verifier.Verify(newToken.Payload(), newToken.Signature())
	checkErr(errVerify)

	// 8. also you can parse and verify in 1 operation
	newToken, err = jwt.ParseAndVerifyString(tokenStr, verifier)
	checkErr(err)

	// 9. get standard claims
	var newClaims jwt.StandardClaims
	errClaims := json.Unmarshal(newToken.RawClaims(), &newClaims)
	checkErr(errClaims)

	// 10. verify claims
	var _ bool = newClaims.IsForAudience("admin")
	var _ bool = newClaims.IsValidAt(time.Now())

	fmt.Printf("Algorithm %v\n", newToken.Header().Algorithm)
	fmt.Printf("Type      %v\n", newToken.Header().Type)
	fmt.Printf("Claims    %v\n", string(newToken.RawClaims()))
	fmt.Printf("Payload   %v\n", string(newToken.Payload()))
	fmt.Printf("Token     %v\n", string(newToken.Raw()))

	// Output:
	// Algorithm HS256
	// Type      JWT
	// Claims    {"jti":"random-unique-string","aud":"admin"}
	// Payload   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJyYW5kb20tdW5pcXVlLXN0cmluZyIsImF1ZCI6ImFkbWluIn0
	// Token     eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJyYW5kb20tdW5pcXVlLXN0cmluZyIsImF1ZCI6ImFkbWluIn0.uNaqGEggmy02lZq8FM7KoUKXhOy-zrSF7inYuzIET9o
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
