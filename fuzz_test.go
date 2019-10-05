package jwt_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/cristalhq/jwt"
	fuzz "github.com/google/gofuzz"
)

func TestFuzzHSSigners(t *testing.T) {
	signers := []struct {
		name string
		new  func([]byte) jwt.Signer
	}{
		{name: "HS256", new: jwt.NewHS256},
		{name: "HS384", new: jwt.NewHS384},
		{name: "HS512", new: jwt.NewHS512},
	}

	for _, signer := range signers {
		err := fuzzSigner(func(f *fuzz.Fuzzer) jwt.Signer {
			var key []byte
			f.Fuzz(&key)
			return signer.new(key)
		})
		if err != nil {
			t.Errorf("error fuzzing %q: %v", signer.name, err)
		}
	}
}

func TestFuzzRSSigners(t *testing.T) {
	signers := []struct {
		name string
		new  func(*rsa.PublicKey, *rsa.PrivateKey) jwt.Signer
	}{
		{name: "RS256", new: jwt.NewRS256},
		{name: "RS384", new: jwt.NewRS384},
		{name: "RS512", new: jwt.NewRS512},
	}

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("error generating rsa key: %v", err)
	}

	for _, signer := range signers {
		err := fuzzSigner(func(f *fuzz.Fuzzer) jwt.Signer {
			return signer.new(&key.PublicKey, key)
		})
		if err != nil {
			t.Errorf("error fuzzing %q: %v", signer.name, err)
		}
	}
}

func TestFuzzNoEncrypt(t *testing.T) {
	err := fuzzSigner(func(*fuzz.Fuzzer) jwt.Signer {
		return jwt.NewNoEncrypt()
	})
	if err != nil {
		t.Errorf("error fuzzing NoEncrypt: %v", err)
	}
}

func TestFuzzEd25519(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	err = fuzzSigner(func(*fuzz.Fuzzer) jwt.Signer {
		if err != nil {
			t.Fatalf("error generating ed25519 key: %v", err)
		}
		return jwt.NewEd25519(public, private)
	})
	if err != nil {
		t.Errorf("error fuzzing Ed25519: %v", err)
	}
}

func fuzzSigner(signerFunc func(f *fuzz.Fuzzer) jwt.Signer) error {
	f := fuzz.New()

	for i := 0; i < 100; i++ {
		signer := signerFunc(f)
		builder := jwt.NewTokenBuilder(signer)

		claims := &jwt.StandardClaims{}
		f.NilChance(0.25).Fuzz(&claims)
		token, err := builder.Build(claims)
		if err != nil {
			return err
		}
		token.Raw()
	}
	return nil
}
