package jwt_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	mathRand "math/rand"
	"testing"
	"time"
	"unsafe"

	"github.com/cristalhq/jwt/v2"
)

func BenchmarkEDSA(b *testing.B) {
	pubKey, privKey, keyErr := ed25519.GenerateKey(rand.Reader)
	if keyErr != nil {
		b.Fatal(keyErr)
	}
	signer, signerErr := jwt.NewSignerEdDSA(privKey)
	if signerErr != nil {
		b.Fatal(signerErr)
	}
	verifier, verifierErr := jwt.NewVerifierEdDSA(pubKey)
	if verifierErr != nil {
		b.Fatal(verifierErr)
	}
	builder := jwt.NewBuilder(signer)
	b.Run("Sign-"+string(jwt.EdDSA), func(b *testing.B) {
		runSignerBench(b, builder)
	})
	b.Run("Verify-"+string(jwt.EdDSA), func(b *testing.B) {
		runVerifyBench(b, builder, verifier)
	})
}

func BenchmarkES(b *testing.B) {
	esAlgos := map[jwt.Algorithm]elliptic.Curve{
		jwt.ES256: elliptic.P256(),
		jwt.ES384: elliptic.P384(),
		jwt.ES512: elliptic.P521(),
	}
	for algo, curve := range esAlgos {
		key, keyErr := ecdsa.GenerateKey(curve, rand.Reader)
		if keyErr != nil {
			b.Fatal(keyErr)
		}
		signer, signerErr := jwt.NewSignerES(algo, key)
		if signerErr != nil {
			b.Fatal(signerErr)
		}
		verifier, verifierErr := jwt.NewVerifierES(algo, &key.PublicKey)
		if verifierErr != nil {
			b.Fatal(verifierErr)
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

func BenchmarkPS(b *testing.B) {
	psAlgos := []jwt.Algorithm{jwt.PS256, jwt.PS384, jwt.PS512}
	for _, algo := range psAlgos {
		key, keyErr := rsa.GenerateKey(rand.Reader, 2048)
		if keyErr != nil {
			b.Fatal(keyErr)
		}
		signer, signerErr := jwt.NewSignerPS(algo, key)
		if signerErr != nil {
			b.Fatal(signerErr)
		}
		verifier, verifierErr := jwt.NewVerifierPS(algo, &key.PublicKey)
		if verifierErr != nil {
			b.Fatal(verifierErr)
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

func BenchmarkRS(b *testing.B) {
	rsAlgos := []jwt.Algorithm{jwt.RS256, jwt.RS384, jwt.RS512}
	for _, algo := range rsAlgos {
		key, keyErr := rsa.GenerateKey(rand.Reader, 2048)
		if keyErr != nil {
			b.Fatal(keyErr)
		}
		signer, signerErr := jwt.NewSignerRS(algo, key)
		if signerErr != nil {
			b.Fatal(signerErr)
		}
		verifier, verifierErr := jwt.NewVerifierRS(algo, &key.PublicKey)
		if verifierErr != nil {
			b.Fatal(verifierErr)
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

func BenchmarkHS(b *testing.B) {
	key := []byte("12345")
	hsAlgos := []jwt.Algorithm{jwt.HS256, jwt.HS384, jwt.HS512}
	for _, algo := range hsAlgos {
		signer, signerErr := jwt.NewSignerHS(algo, key)
		if signerErr != nil {
			b.Fatal(signerErr)
		}
		verifier, verifierErr := jwt.NewVerifierHS(algo, key)
		if verifierErr != nil {
			b.Fatal(verifierErr)
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

	sink := uintptr(0)
	for i := 0; i < b.N; i++ {
		token, tokenErr := builder.Build(jwt.StandardClaims{
			ID:       "id",
			Issuer:   "sdf",
			IssuedAt: jwt.NewNumericDate(time.Now()),
		})
		if tokenErr != nil {
			b.Fatal(tokenErr)
		}
		sink += uintptr(unsafe.Pointer(token))
	}

	if mathRand.Intn(10000) > 9999 {
		b.Log(sink)
	}
}

func runVerifyBench(b *testing.B, builder *jwt.Builder, verifier jwt.Verifier) {
	builder.Build(jwt.StandardClaims{
		ID:       "id",
		Issuer:   "sdf",
		IssuedAt: jwt.NewNumericDate(time.Now()),
	})
	token, tokenErr := builder.Build(jwt.StandardClaims{
		ID:       "id",
		Issuer:   "sdf",
		IssuedAt: jwt.NewNumericDate(time.Now()),
	})
	if tokenErr != nil {
		b.Fatal(tokenErr)
	}

	b.ReportAllocs()
	sink := uintptr(0)
	for i := 0; i < b.N; i++ {
		verificationErr := verifier.Verify(token.Payload(), token.Signature())
		sink += uintptr(unsafe.Pointer(&verificationErr))
		if verificationErr != nil {
			b.Fatal(verificationErr)
		}
	}

	if mathRand.Intn(10000) > 9999 {
		b.Log(sink)
	}
}
