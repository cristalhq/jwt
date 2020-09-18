package jwt

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

func TestBuild(t *testing.T) {
	f := func(signer Signer, claims interface{}, want string) {
		t.Helper()

		builder := NewBuilder(signer)
		token, err := builder.BuildBytes(claims)
		if err != nil {
			t.Error(err)
		}

		raw := string(token)
		if raw != want {
			t.Errorf("want %v,\n got %v", want, raw)
		}
	}

	f(
		mustSigner(NewSignerHS(HS256, []byte("test-key-256"))),
		&RegisteredClaims{
			ID:       "just an id",
			Audience: Audience([]string{"audience"}),
		},
		`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqdXN0IGFuIGlkIiwiYXVkIjoiYXVkaWVuY2UifQ.t5oEdZGp0Qbth7lo5fZlV_o4-r9gMoYBSktXbarjWoo`,
	)
}

func TestBuildHeader(t *testing.T) {
	f := func(signer Signer, header Header, want string) {
		t.Helper()

		token, err := NewBuilder(signer).Build(&RegisteredClaims{})
		if err != nil {
			t.Error(err)
		}

		want = toBase64(want)
		raw := string(token.RawHeader())
		if raw != want {
			t.Errorf("\nwant %v,\n got %v", want, raw)
		}
	}

	key := []byte("key")
	f(
		mustSigner(NewSignerHS(HS256, key)),
		Header{Algorithm: HS256, Type: "JWT"},
		`{"alg":"HS256","typ":"JWT"}`,
	)
	f(
		mustSigner(NewSignerHS(HS384, key)),
		Header{Algorithm: HS384, Type: "JWT"},
		`{"alg":"HS384","typ":"JWT"}`,
	)
	f(
		mustSigner(NewSignerHS(HS512, key)),
		Header{Algorithm: HS512, Type: "JWT"},
		`{"alg":"HS512","typ":"JWT"}`,
	)

	f(
		mustSigner(NewSignerRS(RS256, rsaPrivateKey1)),
		Header{Algorithm: RS256, Type: "JWT"},
		`{"alg":"RS256","typ":"JWT"}`,
	)
	f(
		mustSigner(NewSignerRS(RS384, rsaPrivateKey1)),
		Header{Algorithm: RS384, Type: "JWT"},
		`{"alg":"RS384","typ":"JWT"}`,
	)
	f(
		mustSigner(NewSignerRS(RS512, rsaPrivateKey1)),
		Header{Algorithm: RS512, Type: "JWT"},
		`{"alg":"RS512","typ":"JWT"}`,
	)
}

func TestBuildMalformed(t *testing.T) {
	f := func(signer Signer, claims interface{}) {
		t.Helper()

		builder := NewBuilder(signer)
		_, err := builder.BuildBytes(claims)
		if err == nil {
			t.Error("want err, got nil")
		}
	}

	f(
		badSigner{},
		nil,
	)
	f(
		mustSigner(NewSignerHS(HS256, []byte("test-key"))),
		badSigner.Algorithm,
	)
}

var tests = []struct {
	key *ecdsa.PrivateKey
	alg Algorithm
}{
	{testKeyEC256, ES256},
	{testKeyEC384, ES384},
	{testKeyEC521, ES512},
}

var mybenchClaims = &struct {
	RegisteredClaims
}{
	RegisteredClaims: RegisteredClaims{
		Issuer:   "benchmark",
		IssuedAt: NewNumericDate(time.Now()),
	},
}

func Test_Two_ECDSA(t *testing.T) {
	for _, test := range tests {
		signer, err := NewSignerES(test.alg, test.key)
		if err != nil {
			t.Fatal(err)
		}
		bui := NewBuilder(signer)
		token, err := bui.BuildBytes(mybenchClaims)
		if err != nil {
			t.Fatal(err)
		}

		verifier, err := NewVerifierES(test.alg, &test.key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		t.Run("check-"+test.alg.String(), func(t *testing.T) {
			obj, err := ParseAndVerify(token, verifier)
			if err != nil {
				t.Fatal(err)
			}
			err = json.Unmarshal(obj.RawClaims(), new(map[string]interface{}))
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func mustParseECKey(s string) *ecdsa.PrivateKey {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		panic("invalid PEM")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return key
}

var testKeyEC256 = mustParseECKey(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBOm12aaXvqSzysOSGV2yL/xKY3kCtaOfAPY1KQN2sTJoAoGCCqGSM49
AwEHoUQDQgAEX0iTLAcGqlWeGIRtIk0G2PRgpf/6gLxOTyMAdriP4NLRkuu+9Idt
y3qmEizRC0N81j84E213/LuqLqnsrgfyiw==
-----END EC PRIVATE KEY-----`)

var testKeyEC384 = mustParseECKey(`-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBluSyfK9BEPc9y944ZLahd4xHRVse64iCeEC5gBQ4UM1961bsEthUC
NKXyTGTBuW2gBwYFK4EEACKhZANiAAR3Il6V61OwAnb6oYm4hQ4TVVaGQ2QGzrSi
eYGoRewNhAaZ8wfemWX4fww7yNi6AmUzWV8Su5Qq3dtN3nLpKUEaJrTvfjtowrr/
ZtU1fZxzI/agEpG2+uLFW6JNdYzp67w=
-----END EC PRIVATE KEY-----`)

var testKeyEC521 = mustParseECKey(`-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBH31vhkSH+x+J8C/xf/PRj81u3MCqgiaGdW1S1jcjEuikczbbX689
9ETHGCPtHEWw/Il1RAFaKMvndmfDVd/YapmgBwYFK4EEACOhgYkDgYYABAGNpBDA
Lx6rKQXWdWQR581uw9dTuV8zjmkSpLZ3k0qLHVlOqt00AfEL4NO+E7fxh4SuAZPb
RDMu2lx4lWOM2EyFvgFIyu8xlA9lEg5GKq+A7+y5r99RLughiDd52vGnudMspHEy
x6IpwXzTZR/T8TkluL3jDWtVNFxGBf/aEErnpeLfRQ==
-----END EC PRIVATE KEY-----`)

func toBase64(s string) string {
	buf := make([]byte, b64EncodedLen(len(s)))
	base64.RawURLEncoding.Encode(buf, []byte(s))
	return string(buf)
}

type badSigner struct{}

func (badSigner) SignSize() int {
	return 0
}
func (badSigner) Algorithm() Algorithm {
	return "bad"
}
func (badSigner) Sign(payload []byte) ([]byte, error) {
	return nil, errors.New("error by design")
}
func (badSigner) Verify(payload, signature []byte) error {
	return errors.New("error by design")
}
