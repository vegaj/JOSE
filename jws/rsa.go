package jws

import (
	"crypto/rsa"
	"errors"

	"github.com/vegaj/JOSE/jwa"
)

func rsaSignature(message []byte, opt *Options) ([]byte, error) {

	switch opt.Algorithm {
	case jwa.RS256, jwa.RS384, jwa.RS512: //Ok
	default: //It's not RSA kind.
		return nil, errors.New(jwa.ErrInvalidAlgorithm)
	}

	return jwa.RSASign(message, opt.Private().(*rsa.PrivateKey), opt.Algorithm)
}

func rsaVerify(message, signature []byte, opt *Options) error {
	switch opt.Algorithm {
	case jwa.RS256, jwa.RS384, jwa.RS512: //Ok
	default: //It's not RSA kind.
		return errors.New(jwa.ErrInvalidAlgorithm)
	}

	if err := jwa.RSAVerify(message, signature, opt.Public().(*rsa.PublicKey), opt.Algorithm); err != nil {
		return errors.New(jwa.ErrAlteredMessage)
	}
	return nil
}
