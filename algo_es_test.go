package jwt

import (
	"crypto/ecdsa"
	"testing"
)

func TestES(t *testing.T) {
	testCases := []struct {
		alg        Algorithm
		privateKey *ecdsa.PrivateKey
		publicKey  *ecdsa.PublicKey
		wantErr    error
	}{
		{ES256, ecdsaPrivateKey256, ecdsaPublicKey256, nil},
		{ES384, ecdsaPrivateKey384, ecdsaPublicKey384, nil},
		{ES512, ecdsaPrivateKey521, ecdsaPublicKey521, nil},

		{ES256, ecdsaPrivateKey256, ecdsaPublicKey256Another, ErrInvalidSignature},
		{ES384, ecdsaPrivateKey384, ecdsaPublicKey384Another, ErrInvalidSignature},
		{ES512, ecdsaPrivateKey521, ecdsaPublicKey521Another, ErrInvalidSignature},

		{ES256, ecdsaPrivateKey256Another, ecdsaPublicKey256, ErrInvalidSignature},
		{ES384, ecdsaPrivateKey384Another, ecdsaPublicKey384, ErrInvalidSignature},
		{ES512, ecdsaPrivateKey521Another, ecdsaPublicKey521, ErrInvalidSignature},
	}

	for _, tc := range testCases {
		signer, err := NewSignerES(tc.alg, tc.privateKey)
		mustOk(t, err)

		verifier, err := NewVerifierES(tc.alg, tc.publicKey)
		mustOk(t, err)

		token, err := NewBuilder(signer).Build(simplePayload)
		mustOk(t, err)

		err = verifier.Verify(token)
		mustEqual(t, err, tc.wantErr)
	}
}

func TestES_BadKeys(t *testing.T) {
	testCases := []struct {
		err     error
		wantErr error
	}{
		{getErr(NewSignerES(ES256, nil)), ErrNilKey},
		{getErr(NewSignerES(ES384, nil)), ErrNilKey},
		{getErr(NewSignerES(ES512, nil)), ErrNilKey},

		{getErr(NewSignerES("foo", ecdsaPrivateKey384)), ErrUnsupportedAlg},

		{getErr(NewSignerES(ES256, ecdsaPrivateKey384)), ErrInvalidKey},
		{getErr(NewSignerES(ES256, ecdsaPrivateKey521)), ErrInvalidKey},
		{getErr(NewSignerES(ES384, ecdsaPrivateKey256)), ErrInvalidKey},
		{getErr(NewSignerES(ES384, ecdsaPrivateKey521)), ErrInvalidKey},
		{getErr(NewSignerES(ES512, ecdsaPrivateKey256)), ErrInvalidKey},
		{getErr(NewSignerES(ES512, ecdsaPrivateKey384)), ErrInvalidKey},

		{getErr(NewVerifierES(ES256, nil)), ErrNilKey},
		{getErr(NewVerifierES(ES384, nil)), ErrNilKey},
		{getErr(NewVerifierES(ES512, nil)), ErrNilKey},

		{getErr(NewVerifierES("boo", ecdsaPublicKey384)), ErrUnsupportedAlg},

		{getErr(NewVerifierES(ES256, ecdsaPublicKey384)), ErrInvalidKey},
		{getErr(NewVerifierES(ES256, ecdsaPublicKey521)), ErrInvalidKey},
		{getErr(NewVerifierES(ES384, ecdsaPublicKey256)), ErrInvalidKey},
		{getErr(NewVerifierES(ES384, ecdsaPublicKey521)), ErrInvalidKey},
		{getErr(NewVerifierES(ES512, ecdsaPublicKey256)), ErrInvalidKey},
		{getErr(NewVerifierES(ES512, ecdsaPublicKey384)), ErrInvalidKey},
	}

	for _, tc := range testCases {
		mustEqual(t, tc.err, tc.wantErr)
	}
}

var (
	ecdsaPrivateKey256 = mustParseECKey(testKeyES256)
	ecdsaPrivateKey384 = mustParseECKey(testKeyES384)
	ecdsaPrivateKey521 = mustParseECKey(testKeyES521)

	ecdsaPublicKey256 = &ecdsaPrivateKey256.PublicKey
	ecdsaPublicKey384 = &ecdsaPrivateKey384.PublicKey
	ecdsaPublicKey521 = &ecdsaPrivateKey521.PublicKey

	ecdsaPrivateKey256Another = mustParseECKey(testKeyES256Another)
	ecdsaPrivateKey384Another = mustParseECKey(testKeyES384Another)
	ecdsaPrivateKey521Another = mustParseECKey(testKeyES521Another)

	ecdsaPublicKey256Another = &ecdsaPrivateKey256Another.PublicKey
	ecdsaPublicKey384Another = &ecdsaPrivateKey384Another.PublicKey
	ecdsaPublicKey521Another = &ecdsaPrivateKey521Another.PublicKey
)

// To generate keys:
// ES256
// openssl ecparam -name prime256v1 -genkey -noout -out es256-private.pem
// ES384
// openssl ecparam -name secp384r1 -genkey -noout -out es384-private.pem
// ES512
// openssl ecparam -name secp521r1 -genkey -noout -out es521-private.pem
const (
	testKeyES256 = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM+a8cZ6BjdZBYy7pMIqmWsHKSmAZhZ/RTeSkmzPKohfoAoGCCqGSM49
AwEHoUQDQgAE18xDMC6wYt4TJakM3DeHBmLoyEin/vNaJl3g2V3xfGSmuZ1GL2Pm
DO00CX84Vj/pHaIGQYgXLm8zuxiBMaNIXA==
-----END EC PRIVATE KEY-----`

	testKeyES384 = `-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCi1H43WBIeJVC2kN/asAJAte564UyXAb+ZIjyB+jF92BfcOrDkQkJV
8er9/kZCSCegBwYFK4EEACKhZANiAAQP3m6j/r1X70mQ38BEArSwFkr/jztwHB9/
kHDd8paBykz4wjI2TqIANZ+7d6EWQNL/kEcxfd6CUsq0vRMi8cVG1+Yw1ogLcKgd
hdoGc7IiV1oD6w6iX5PfqUdj2lfP6qU=
-----END EC PRIVATE KEY-----`

	testKeyES521 = `-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBxKNCQAGpI4T9l6yxN8jCTc5KzF4wlnDF1M8uNebQfsgl9RXwAb34
8YF1Bip5kkf6OFh6hFBDK/J5VgqSrgFMXNigBwYFK4EEACOhgYkDgYYABACju/hE
QgtvmUP6ZToxo2f7nO/Z9b2dOArvZE9qLqUKi8p8vhLd085YJ+PUAc9BRPSSUAsR
0g4FvPJKFBzO5KcdIAD/Rnqt4sjBiU+SsVqeG0YWbuotFqbzYu9J0vMhPiwaZa73
HIoOXZT7jXPe6TePSmBodJuj3i0hgtlbvC3dQDccyw==
-----END EC PRIVATE KEY-----`

	testKeyES256Another = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM9p5Ce0A5nPx4LxiA92TP3wDNiXDyK17sn8zZsvaseSoAoGCCqGSM49
AwEHoUQDQgAEiX+f1oVkt5F2lvpFmerr2OoFRalnqK0yNx0d6vph6MsAcfDC309P
TjEIWn3NQNHI8XROvhODPxiSbXumbnuoOw==
-----END EC PRIVATE KEY-----`

	testKeyES384Another = `-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCRwcoUBpkkIp1geqykLRqrsoQ0swsJJTVyVNu6lDshoOYAOz4NwUw2
iRl0o/Xm5cCgBwYFK4EEACKhZANiAARz6nE/bj22RdSKRENMDeF5V+VE20tN1Nzk
tvbmDePQD8538gBGQJzv+lVWNNmsx5MD0To1BBc2HbemdKrXmnLnwOJ2a+zsLqCa
JlXGCIn5G1gL2sfMbeNn/WB3MPOQna0=
-----END EC PRIVATE KEY-----`

	testKeyES521Another = `-----BEGIN EC PRIVATE KEY-----
MIHbAgEBBEGSdts6vIYr2KEQxjkfMys7RfxDUidql0AHl7RvbzdiVVDaVjx7g+Cl
tZpqDMe/sYE813duYRpd9xXCFSRVDjHBXqAHBgUrgQQAI6GBiQOBhgAEAQsdOs3W
huEJWa6h86aTP980Pdbme6fkdTERq9mvI1zn8L4211scGA6cbqNeLNn6wt/v7iGb
HNjmL7z8CLwOgqHDASUN5UtdJC+gPDJi7WllkCz7uM2iwvZQ339bTN+bywiHQUrQ
MvbD7c0RONrhLoch5W6TlWCMj9f4EkQQEfk63Q8F
-----END EC PRIVATE KEY-----`
)
