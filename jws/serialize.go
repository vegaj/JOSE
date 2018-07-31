package jws

//SignSettings signature settings
type SignSettings struct {
	//Algorithm to be used must be a Signature Algorithm Name found in jwa package.
	Algorithm string
	//SingKey is the key to be used to create the digital signature. Same as VerifyKey in HSXXX cases.
	SingKey []byte
	//VerifyKey is the key to be used to verify the digital signature.
	VerifyKey []byte
}

//SignWith implements the jwa.Signer interface
func (s SignSettings) SignWith() []byte {
	return s.SingKey
}

//VerifyWith implements the jwa.Verifier interface
func (s SignSettings) VerifyWith() []byte {
	return s.VerifyKey
}
