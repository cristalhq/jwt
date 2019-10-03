# jwt

[![Build Status][build-img]][build-url]
[![GoDoc][doc-img]][doc-url]
[![Go Report Card][reportcard-img]][reportcard-url]
[![Go Report Card][coverage-img]][coverage-url]

JSON Web Tokens for Go

## Features

* Simple API.
* Optimized for speed.
* Dependency-free.

## Install

Go version 1.13

```
go get github.com/cristalhq/jwt
```

## Example

```go
signer := jwt.NewHS256([]byte(`secret`))
builder := jwt.NewTokenBuilder(signer)

claims := &jwt.StandardClaims{
    Audience: []string{"admin"},
    ID:       "random-unique-string",
}
token, _ := builder.Build(claims)

raw := token.Raw() // JWT signed token
```

## Documentation

See [these docs](https://godoc.org/github.com/cristalhq/jwt).

## License

[MIT License](LICENSE).

[build-img]: https://github.com/cristalhq/jwt/workflows/Go/badge.svg
[build-url]: https://github.com/cristalhq/jwt/actions
[doc-img]: https://godoc.org/github.com/cristalhq/jwt?status.svg
[doc-url]: https://godoc.org/github.com/cristalhq/jwt
[reportcard-img]: https://goreportcard.com/badge/cristalhq/jwt
[reportcard-url]: https://goreportcard.com/report/cristalhq/jwt
[coverage-img]: https://coveralls.io/repos/github/cristalhq/jwt/badge.svg?branch=master
[coverage-url]: https://coveralls.io/github/cristalhq/jwt?branch=master
