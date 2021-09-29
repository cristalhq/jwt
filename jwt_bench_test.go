package jwt_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/cristalhq/jwt/v4"
)

func BenchmarkAlgEDSA(b *testing.B) {
	pubKey, privKey, errKey := ed25519.GenerateKey(rand.Reader)
	if errKey != nil {
		b.Fatal(errKey)
	}
	signer, errSigner := jwt.NewSignerEdDSA(privKey)
	if errSigner != nil {
		b.Fatal(errSigner)
	}
	verifier, errVerifier := jwt.NewVerifierEdDSA(pubKey)
	if errVerifier != nil {
		b.Fatal(errVerifier)
	}

	builder := jwt.NewBuilder(signer)
	b.Run("Sign-"+string(jwt.EdDSA), func(b *testing.B) {
		runSignerBench(b, builder)
	})
	b.Run("Verify-"+string(jwt.EdDSA), func(b *testing.B) {
		runVerifyBench(b, builder, verifier)
	})
}

func BenchmarkAlgES(b *testing.B) {
	esAlgos := map[jwt.Algorithm]elliptic.Curve{
		jwt.ES256: elliptic.P256(),
		jwt.ES384: elliptic.P384(),
		jwt.ES512: elliptic.P521(),
	}
	for algo, curve := range esAlgos {
		key, errKey := ecdsa.GenerateKey(curve, rand.Reader)
		if errKey != nil {
			b.Fatal(errKey)
		}
		signer, errSigner := jwt.NewSignerES(algo, key)
		if errSigner != nil {
			b.Fatal(errSigner)
		}
		verifier, errVerifier := jwt.NewVerifierES(algo, &key.PublicKey)
		if errVerifier != nil {
			b.Fatal(errVerifier)
		}

		builder := jwt.NewBuilder(signer)
		b.Run("Sign-"+string(algo), func(b *testing.B) {
			runSignerBench(b, builder)
		})
		b.Run("Verify-"+string(algo), func(b *testing.B) {
			runVerifyBench(b, builder, verifier)
		})
	}
}

func BenchmarkAlgPS(b *testing.B) {
	psAlgos := []jwt.Algorithm{jwt.PS256, jwt.PS384, jwt.PS512}
	for _, algo := range psAlgos {
		key, errKey := rsa.GenerateKey(rand.Reader, 2048)
		if errKey != nil {
			b.Fatal(errKey)
		}
		signer, errSigner := jwt.NewSignerPS(algo, key)
		if errSigner != nil {
			b.Fatal(errSigner)
		}
		verifier, errVerifier := jwt.NewVerifierPS(algo, &key.PublicKey)
		if errVerifier != nil {
			b.Fatal(errVerifier)
		}

		builder := jwt.NewBuilder(signer)
		b.Run("Sign-"+string(algo), func(b *testing.B) {
			runSignerBench(b, builder)
		})
		b.Run("Verify-"+string(algo), func(b *testing.B) {
			runVerifyBench(b, builder, verifier)
		})
	}
}

func BenchmarkAlgRS(b *testing.B) {
	rsAlgos := []jwt.Algorithm{jwt.RS256, jwt.RS384, jwt.RS512}
	for _, algo := range rsAlgos {
		key, errKey := rsa.GenerateKey(rand.Reader, 2048)
		if errKey != nil {
			b.Fatal(errKey)
		}
		signer, errSigner := jwt.NewSignerRS(algo, key)
		if errSigner != nil {
			b.Fatal(errSigner)
		}
		verifier, errVerifier := jwt.NewVerifierRS(algo, &key.PublicKey)
		if errVerifier != nil {
			b.Fatal(errVerifier)
		}

		builder := jwt.NewBuilder(signer)
		b.Run("Sign-"+string(algo), func(b *testing.B) {
			runSignerBench(b, builder)
		})
		b.Run("Verify-"+string(algo), func(b *testing.B) {
			runVerifyBench(b, builder, verifier)
		})
	}
}

func BenchmarkAlgHS(b *testing.B) {
	key := []byte("12345")
	hsAlgos := []jwt.Algorithm{jwt.HS256, jwt.HS384, jwt.HS512}
	for _, algo := range hsAlgos {
		signer, errSigner := jwt.NewSignerHS(algo, key)
		if errSigner != nil {
			b.Fatal(errSigner)
		}
		verifier, errVerifier := jwt.NewVerifierHS(algo, key)
		if errVerifier != nil {
			b.Fatal(errVerifier)
		}

		builder := jwt.NewBuilder(signer)
		b.Run("Sign-"+string(algo), func(b *testing.B) {
			runSignerBench(b, builder)
		})
		b.Run("Verify-"+string(algo), func(b *testing.B) {
			runVerifyBench(b, builder, verifier)
		})
	}
}

func runSignerBench(b *testing.B, builder *jwt.Builder) {
	b.ReportAllocs()

	claims := jwt.RegisteredClaims{
		ID:       "id",
		Issuer:   "sdf",
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}

	var dummy int
	for i := 0; i < b.N; i++ {
		token, err := builder.Build(claims)
		if err != nil {
			b.Fatal(err)
		}
		dummy += int(token.PayloadPart()[0])
	}
	sink(dummy)
}

func runVerifyBench(b *testing.B, builder *jwt.Builder, verifier jwt.Verifier) {
	const tokensCount = 32
	tokens := make([]*jwt.Token, 0, tokensCount)
	for i := 0; i < tokensCount; i++ {
		token, err := builder.Build(jwt.RegisteredClaims{
			ID:       "id",
			Issuer:   "sdf",
			IssuedAt: jwt.NewNumericDate(time.Now()),
		})
		if err != nil {
			b.Fatal(err)
		}
		tokens = append(tokens, token)
	}

	b.ReportAllocs()
	var dummy int
	for i := 0; i < b.N/tokensCount; i++ {
		for _, token := range tokens {
			err := verifier.Verify(token)
			if err != nil {
				b.Fatal(err)
			}
			dummy++
		}
	}
	sink(dummy)
}

func sink(v interface{}) {
	fmt.Fprint(io.Discard, v)
}
