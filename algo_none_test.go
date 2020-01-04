package jwt

import (
	"bytes"
	"testing"
)

func TestNone(t *testing.T) {
	signer := NewNoEncrypt()

	if signer.Algorithm() != NoEncryption {
		t.Errorf("want %#v, got #%v", NoEncryption, signer.Algorithm())
	}

	sign, err := signer.Sign(nil)
	if err != nil {
		t.Errorf("want nil, got #%v", err)
	}
	if sign != nil {
		t.Errorf("want nil, got #%v", sign)
	}

	sign, err = signer.Sign([]byte(`test`))
	if err != nil {
		t.Errorf("want nil, got #%v", err)
	}
	if !bytes.Equal(sign, []byte("test")) {
		t.Errorf("want nil, got #%v", sign)
	}

	err = signer.Verify(nil, nil)
	if err != nil {
		t.Errorf("want nil, got #%v", err)
	}
	err = signer.Verify([]byte(`test`), []byte(`test`))
	if err != nil {
		t.Errorf("want nil, got #%v", err)
	}
}
