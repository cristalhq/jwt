package jwt_test

import (
	"math/rand"
	"testing"
	"time"
	"unsafe"

	"github.com/cristalhq/jwt/v2"
)

func BenchmarkSignerHS(b *testing.B) {
	b.StopTimer()

	key := []byte("12345")
	signer, signerErr := jwt.NewSignerHS(jwt.HS256, key)
	if signerErr != nil {
		b.Fatal(signerErr)
	}
	builder := jwt.NewBuilder(signer)

	b.ReportAllocs()
	b.StartTimer()

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

	if rand.Intn(10000) > 9999 {
		b.Log(sink)
	}
}
