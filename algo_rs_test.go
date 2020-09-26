package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
)

var rsaPublicKey1 *rsa.PublicKey
var rsaPublicKey2 *rsa.PublicKey
var rsaPrivateKey1 *rsa.PrivateKey
var rsaPrivateKey2 *rsa.PrivateKey

func init() {
	fromBase10 := func(base10 string) *big.Int {
		i, _ := new(big.Int).SetString(base10, 10)
		return i
	}

	rsaPublicKey1 = &rsa.PublicKey{
		N: fromBase10("14314132931241006650998084889274020608918049032671858325988396851334124245188214251956198731333464217832226406088020736932173064754214329009979944037640912127943488972644697423190955557435910767690712778463524983667852819010259499695177313115447116110358524558307947613422897787329221478860907963827160223559690523660574329011927531289655711860504630573766609239332569210831325633840174683944553667352219670930408593321661375473885147973879086994006440025257225431977751512374815915392249179976902953721486040787792801849818254465486633791826766873076617116727073077821584676715609985777563958286637185868165868520557"),
		E: 3,
	}
	rsaPrivateKey1 = &rsa.PrivateKey{
		PublicKey: *rsaPublicKey1,
		D:         fromBase10("9542755287494004433998723259516013739278699355114572217325597900889416163458809501304132487555642811888150937392013824621448709836142886006653296025093941418628992648429798282127303704957273845127141852309016655778568546006839666463451542076964744073572349705538631742281931858219480985907271975884773482372966847639853897890615456605598071088189838676728836833012254065983259638538107719766738032720239892094196108713378822882383694456030043492571063441943847195939549773271694647657549658603365629458610273821292232646334717612674519997533901052790334279661754176490593041941863932308687197618671528035670452762731"),
		Primes: []*big.Int{
			fromBase10("130903255182996722426771613606077755295583329135067340152947172868415809027537376306193179624298874215608270802054347609836776473930072411958753044562214537013874103802006369634761074377213995983876788718033850153719421695468704276694983032644416930879093914927146648402139231293035971427838068945045019075433"),
			fromBase10("109348945610485453577574767652527472924289229538286649661240938988020367005475727988253438647560958573506159449538793540472829815903949343191091817779240101054552748665267574271163617694640513549693841337820602726596756351006149518830932261246698766355347898158548465400674856021497190430791824869615170301029"),
		},
	}

	rsaPublicKey2 = &rsa.PublicKey{
		N: fromBase10("887256638780856047914581579814082241228904817182093261763058947771445376334361454028526564964284108022499562499436107360797167855238681264022398768822093355881651855771536641100347179464316604983028325045398953751392004347747368839824636917782721516826693522992183854650791268736264416865889799352514216298521461994511678593557464913439951619056304159812403323561755303818800310137159146108075344562143531014989113550013919515074346824023514684979514198941230125010212380546452298362548591023662125669118549327451011201031961777374564883854203295916398755760815894642777422649649856180524299517641811337173222323171868"),
		E: 3,
	}
	rsaPrivateKey2 = &rsa.PrivateKey{
		PublicKey: *rsaPublicKey2,
		D:         fromBase10("9542755287494004433998723259516013739278699355114572217325597900889416163458809501304132487555642811888150937392013824621448709836142886006653296025093941418628992648429798282127303704957273845127141852309016655778568546006839666463451542076964744073572349705538631742281931858219480985907271975884773482372966847639853897890615456605598071088189838676728836833012254065983259638538107719766738032720239892094196108713378822882383694456030043492571063441943847195939549773271694647657549658603365629458610273821292232646334717612674519997533901052790334279661754176490593041941863932308687197618671528035670452762731"),
		Primes: []*big.Int{
			fromBase10("118824431543227186571027026092363352199324615266444280871852738808378452065820764461459770308550270192458287541328152308596233985238045601785765785685887955407926672604456991769558426224026688264520894241180697554536183714315783324715006626168049073199347594517685254572389805736483316580732446129950642427691"),
			fromBase10("167151560084187340876600839609071108780428930679164316900248316388276108158369650170260479635956969047912292329416883197284109866041024250716279228267907058587184812901048552331276732325276799660817363854674774994782375599727993270112962045907225952829559312944081207881075710161619024002861307509427534745757"),
		},
	}
}

func TestRS(t *testing.T) {
	f := func(alg Algorithm, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, isCorrectSign bool, wantSign string) {
		t.Helper()

		const payload = `simple-string-payload`

		sign := rsSign(t, alg, privateKey, payload)

		got := base64.StdEncoding.EncodeToString(sign)
		if got != wantSign {
			t.Fatalf("want %q, got %q", wantSign, got)
		}

		err := rsVerify(t, alg, publicKey, payload, sign)
		if err != nil {
			if isCorrectSign {
				t.Fatal(err)
			}
		}
	}

	f(
		RS256, rsaPrivateKey1, rsaPublicKey1,
		true,
		`BjTjE0oRTnpaiEMxni4k73QmBAvw1PV6ODnsp8v/RQr5h/uQ2X59Mw/ft9IjFWHqvgEMLLRRVCj8j/AJ37sIcNiXaoCRkcvLQv1voQu+Ztmc+lV03jKnDjQCIxYB+OxQ1AxIGWCbTZGC45eHMCr1Ha9N4twAKRfYDQzSUL5x02Oj8jyqFWQG3tZuwWpAFx50VImSSQdrOoVJngKp9yWQnAKa/uEmF32ePz1HXLQc2XaQFBNP+Wa6RmU8CtFbiKeRKX3HitX6obQb1YiDtp3fwvi4T1SCW81mq+2JbO8as1FejlS1B3LYZdH5OsGgQeciFogNojMcOenPGH/5zWsw4A==`,
	)
	f(
		RS384, rsaPrivateKey1, rsaPublicKey1,
		true,
		`CELJCnQwM05KugjmXnY94QNiyAD6E6Kg3US/fGD8dkEPUGwaTBBs00bBbdmK4wJaBwEmAzHITY9NFxB6Muw+XbJCSuc84dJeq6r5chz9aMlCwWkMejB/cC7MJ4D24EqChbT5/0hiYgIQ1JS+qXgKNdd8JrUDNklgV61oBZfNB4J9HMDF+PLy0wkJRe1siFzMqVy/ZujPoC1fHvuJlqyjDF8ksgrzc9mZVNBcQLFecFMAw1KRw7ssvNernSnRC7KSSYvToWfndHVUIpLygM5SEF8RJEgZYBanEN4w4XYuU53gtpLw35Iu5vb1tYMXBGcaVRrynJviUBaPJvJ0e16i8Q==`,
	)
	f(
		RS512, rsaPrivateKey1, rsaPublicKey1,
		true,
		`X3z8RIr++dPiZZw1NaslDnZTIQ5PRMtgLv0eFZfJTIaeWmp5m+bI/wsKQZ+x8UCxhYnNYtX/xcnkLaGn/D7ZQNNw5e3lHrXxYKqg5TSuH0wSVC6l1rU6WOkBmvdIe1B7hwenjCUHSAl2AQC/WN4KKpYMpRhW3+gFixs3p9A2X86J9mR3bPfp+eaCernvhNkIp19IC+YMnZuy4Tj7pKiOf/AFemyngDW7OME/ZZ1CuKR//xPBkQmKPnhVnjhPkFmXMHn6KdSmpEE5CbldmmkKQ/PEbIK0P4hYOvjD2kkAWpADn/X+8rBzSGXb8aq6zWJtN1T4uuDmMNaDMYmUI6s0qQ==`,
	)

	f(
		RS256, rsaPrivateKey1, rsaPublicKey2,
		false,
		`BjTjE0oRTnpaiEMxni4k73QmBAvw1PV6ODnsp8v/RQr5h/uQ2X59Mw/ft9IjFWHqvgEMLLRRVCj8j/AJ37sIcNiXaoCRkcvLQv1voQu+Ztmc+lV03jKnDjQCIxYB+OxQ1AxIGWCbTZGC45eHMCr1Ha9N4twAKRfYDQzSUL5x02Oj8jyqFWQG3tZuwWpAFx50VImSSQdrOoVJngKp9yWQnAKa/uEmF32ePz1HXLQc2XaQFBNP+Wa6RmU8CtFbiKeRKX3HitX6obQb1YiDtp3fwvi4T1SCW81mq+2JbO8as1FejlS1B3LYZdH5OsGgQeciFogNojMcOenPGH/5zWsw4A==`,
	)
	f(
		RS384, rsaPrivateKey1, rsaPublicKey2,
		false,
		`CELJCnQwM05KugjmXnY94QNiyAD6E6Kg3US/fGD8dkEPUGwaTBBs00bBbdmK4wJaBwEmAzHITY9NFxB6Muw+XbJCSuc84dJeq6r5chz9aMlCwWkMejB/cC7MJ4D24EqChbT5/0hiYgIQ1JS+qXgKNdd8JrUDNklgV61oBZfNB4J9HMDF+PLy0wkJRe1siFzMqVy/ZujPoC1fHvuJlqyjDF8ksgrzc9mZVNBcQLFecFMAw1KRw7ssvNernSnRC7KSSYvToWfndHVUIpLygM5SEF8RJEgZYBanEN4w4XYuU53gtpLw35Iu5vb1tYMXBGcaVRrynJviUBaPJvJ0e16i8Q==`,
	)
	f(
		RS512, rsaPrivateKey1, rsaPublicKey2,
		false,
		`X3z8RIr++dPiZZw1NaslDnZTIQ5PRMtgLv0eFZfJTIaeWmp5m+bI/wsKQZ+x8UCxhYnNYtX/xcnkLaGn/D7ZQNNw5e3lHrXxYKqg5TSuH0wSVC6l1rU6WOkBmvdIe1B7hwenjCUHSAl2AQC/WN4KKpYMpRhW3+gFixs3p9A2X86J9mR3bPfp+eaCernvhNkIp19IC+YMnZuy4Tj7pKiOf/AFemyngDW7OME/ZZ1CuKR//xPBkQmKPnhVnjhPkFmXMHn6KdSmpEE5CbldmmkKQ/PEbIK0P4hYOvjD2kkAWpADn/X+8rBzSGXb8aq6zWJtN1T4uuDmMNaDMYmUI6s0qQ==`,
	)
}

func rsSign(t *testing.T, alg Algorithm, privateKey *rsa.PrivateKey, payload string) []byte {
	t.Helper()

	signer, errSigner := NewSignerRS(alg, privateKey)
	if errSigner != nil {
		t.Fatal(errSigner)
	}

	sign, errSign := signer.Sign([]byte(payload))
	if errSign != nil {
		t.Fatal(errSign)
	}
	return sign
}

func rsVerify(t *testing.T, alg Algorithm, publicKey *rsa.PublicKey, payload string, sign []byte) error {
	t.Helper()

	verifier, errVerifier := NewVerifierRS(alg, publicKey)
	if errVerifier != nil {
		t.Fatal(errVerifier)
	}
	return verifier.Verify([]byte(payload), sign)
}
