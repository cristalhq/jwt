package jwt_test

import (
	"encoding/json"
	"fmt"

	"github.com/cristalhq/jwt"
)

func Example_BuildSimple() {
	key := []byte(`secret`)
	signer, _ := jwt.NewHS256(key)
	builder := jwt.NewTokenBuilder(signer)

	claims := &jwt.StandardClaims{
		Audience: []string{"admin"},
		ID:       "random-unique-string",
	}
	token, errBuild := builder.Build(claims)
	checkErr(errBuild)

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

type userClaims struct {
	jwt.StandardClaims

	IsAdministrator bool   `json:"is_admin"`
	Email           string `json:"email"`
}

func (u *userClaims) MarshalBinary() ([]byte, error) {
	return json.Marshal(u)
}

func Example_BuildUserClaims() {
	key := []byte(`secret`)
	signer, _ := jwt.NewHS256(key)
	builder := jwt.NewTokenBuilder(signer)

	claims := &userClaims{
		StandardClaims: jwt.StandardClaims{
			Audience: []string{"admin"},
			ID:       "random-unique-string",
		},
		IsAdministrator: true,
		Email:           "foo@bar.baz",
	}
	token, errBuild := builder.Build(claims)
	checkErr(errBuild)

	fmt.Printf("Claims    %v\n", string(token.RawClaims()))
	fmt.Printf("Payload   %v\n", string(token.Payload()))
	fmt.Printf("Token     %v\n", string(token.Raw()))

	// Output:
	// Claims    {"aud":"admin","jti":"random-unique-string","is_admin":true,"email":"foo@bar.baz"}
	// Payload   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIiwiaXNfYWRtaW4iOnRydWUsImVtYWlsIjoiZm9vQGJhci5iYXoifQ
	// Token     eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIiwiaXNfYWRtaW4iOnRydWUsImVtYWlsIjoiZm9vQGJhci5iYXoifQ.Km2HO5sXMXfrIJMTCA6xf7wamjUABB_glFW3gCGWJCI
}

type dummyClaims map[string]interface{}

func (d *dummyClaims) MarshalBinary() ([]byte, error) {
	return json.Marshal(d)
}

func Example_DummyClaims() {
	key := []byte(`secret`)
	signer, _ := jwt.NewHS256(key)
	builder := jwt.NewTokenBuilder(signer)

	claims := dummyClaims(map[string]interface{}{
		"aUdIeNcE": "@everyone",
		"well":     "well-well-well",
	})
	token, errBuild := builder.Build(&claims)
	checkErr(errBuild)

	fmt.Printf("Claims    %v\n", string(token.RawClaims()))
	fmt.Printf("Payload   %v\n", string(token.Payload()))
	fmt.Printf("Token     %v\n", string(token.Raw()))

	// Output:
	// Claims    {"aUdIeNcE":"@everyone","well":"well-well-well"}
	// Payload   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhVWRJZU5jRSI6IkBldmVyeW9uZSIsIndlbGwiOiJ3ZWxsLXdlbGwtd2VsbCJ9
	// Token     eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhVWRJZU5jRSI6IkBldmVyeW9uZSIsIndlbGwiOiJ3ZWxsLXdlbGwtd2VsbCJ9.vN4rxWHBX4mjG-s0tiM_9ngX_e8KOEyXyEdjsTiTvqI
}
