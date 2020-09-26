package jwt_test

import (
	"fmt"

	"github.com/cristalhq/jwt/v3"
)

func ExampleParse() {
	t := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIn0.dv9-XpY9P8ypm1uWQwB6eKvq3jeyodLA7brhjsf4JVs`

	token, err := jwt.ParseNoVerify([]byte(t))
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

func ExampleParseAndVerify() {
	key := []byte(`secret`)
	verifier, _ := jwt.NewVerifierHS(jwt.HS256, key)

	t := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIn0.dv9-XpY9P8ypm1uWQwB6eKvq3jeyodLA7brhjsf4JVs`

	token, err := jwt.Parse([]byte(t), verifier)
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
