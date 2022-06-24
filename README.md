# jwt

[![build-img]][build-url]
[![pkg-img]][pkg-url]
[![reportcard-img]][reportcard-url]
[![coverage-img]][coverage-url]
[![version-img]][version-url]

JSON Web Token for Go [RFC 7519](https://tools.ietf.org/html/rfc7519), also see [jwt.io](https://jwt.io) for more.

The latest version is `v4`.

## Rationale

There are many JWT libraries, but many of them are hard to use (unclear or fixed API), not optimal (unneeded allocations + strange API). This library addresses all these issues. It's simple to read, to use, memory and CPU conservative.

## Features

* Simple API.
* Clean and tested code.
* Optimized for speed.
* Concurrent-safe.
* Dependency-free.
* All well-known algorithms are supported
  * HMAC (HS)
  * RSA (RS)
  * RSA-PSS (PS)
  * ECDSA (ES)
  * EdDSA (EdDSA)
  * or your own!

See [GUIDE.md](https://github.com/cristalhq/jwt/blob/main/GUIDE.md) for more details.

## Install

Go version 1.17+

```
go get github.com/cristalhq/jwt/v4
```

## Example

Build new token:

```go
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
```

Parse and verify token:
```go
// create a Verifier (HMAC in this example)
key := []byte(`secret`)
verifier, err := jwt.NewVerifierHS(jwt.HS256, key)
checkErr(err)

// parse and verify a token
tokenBytes := token.Bytes()
newToken, err := jwt.Parse(tokenBytes, verifier)
checkErr(err)

// or just verify it's signature
err = verifier.Verify(newToken)
checkErr(err)

// get Registered claims
var newClaims jwt.RegisteredClaims
errClaims := json.Unmarshal(newToken.Claims(), &newClaims)
checkErr(errClaims)

// or parse only claims
errParseClaims := jwt.ParseClaims(tokenBytes, verifier, &newClaims)
checkErr(errParseClaims)

// verify claims as you wish
var _ bool = newClaims.IsForAudience("admin")
var _ bool = newClaims.IsValidAt(time.Now())
```

Also see examples: [example_test.go](https://github.com/cristalhq/jwt/blob/main/example_test.go).

## Documentation

See [these docs][pkg-url].

## License

[MIT License](LICENSE).

[build-img]: https://github.com/cristalhq/jwt/workflows/build/badge.svg
[build-url]: https://github.com/cristalhq/jwt/actions
[pkg-img]: https://pkg.go.dev/badge/cristalhq/jwt/v4
[pkg-url]: https://pkg.go.dev/github.com/cristalhq/jwt/v4
[reportcard-img]: https://goreportcard.com/badge/cristalhq/jwt
[reportcard-url]: https://goreportcard.com/report/cristalhq/jwt
[coverage-img]: https://codecov.io/gh/cristalhq/jwt/branch/main/graph/badge.svg
[coverage-url]: https://codecov.io/gh/cristalhq/jwt
[version-img]: https://img.shields.io/github/v/release/cristalhq/jwt
[version-url]: https://github.com/cristalhq/jwt/releases
