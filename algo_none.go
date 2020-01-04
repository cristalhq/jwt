package jwt

type noEncryptAlg struct{}

// NewNoEncrypt returns new Signer without encryption. SHOULD NOT BE USED.
func NewNoEncrypt() Signer {
	return &noEncryptAlg{}
}

func (h noEncryptAlg) Algorithm() Algorithm {
	return NoEncryption
}

func (h noEncryptAlg) Sign(payload []byte) ([]byte, error) {
	return payload, nil
}

func (h noEncryptAlg) Verify(expected, payload []byte) error {
	return nil
}
