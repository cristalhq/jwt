package jwt_test

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/cristalhq/jwt"
)

func Example() {
	// 1. create a signer
	key := []byte(`secret`)
	signer, errSigner := jwt.NewHS256(key)
	checkErr(errSigner)

	// 2. create a builder based on signer
	builder := jwt.NewTokenBuilder(signer)

	// 3. create standard claims (you can use your own)
	claims := &jwt.StandardClaims{
		Audience: []string{"admin"},
		ID:       "random-unique-string",
	}

	// 4. build a token
	token, errBuild := builder.Build(claims)
	checkErr(errBuild)

	// 5. here is your token :)
	_ = token.Raw() // JWT signed token as []byte

	// 6. parse a token (by example received from a request)
	t := token.Raw()
	token, errParse := jwt.Parse(t)
	checkErr(errParse)

	// 7. or just verify signature
	errVerify := signer.Verify(token.Payload(), token.Signature())
	checkErr(errVerify)

	// 8. parse and verify in 1 operation
	token, errCheck := jwt.ParseAndVerify(t, signer)
	checkErr(errCheck)

	// 9. get standard claims
	var newClaims jwt.StandardClaims
	errClaims := json.Unmarshal(token.RawClaims(), &newClaims)
	checkErr(errClaims)

	// 10. validate standard claims (or create your own checks)
	v := jwt.NewValidator(
		jwt.ExpirationTimeChecker(time.Now()),
		jwt.AudienceChecker(jwt.Audience([]string{"admin"})),
	)
	errValidate := v.Validate(&newClaims)
	checkErr(errValidate)

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
