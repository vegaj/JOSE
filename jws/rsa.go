package jws

import (
	"errors"

	"github.com/vegaj/JOSE/jwa"
)

func rsaSignature(message []byte, opt *Options) ([]byte, error) {

	switch opt.Algorithm {
	case jwa.RS256, jwa.RS384, jwa.RS512: //Ok
	default: //It's not RSA kind.
		return nil, errors.New(jwa.ErrInvalidAlgorithm)
	}

	pk, err := opt.Private()
	if err != nil {
		return nil, err
	}

	return jwa.RSASign(message, pk, opt.Algorithm)
}

func rsaVerify(message, signature []byte, opt *Options) error {
	switch opt.Algorithm {
	case jwa.RS256, jwa.RS384, jwa.RS512: //Ok
	default: //It's not RSA kind.
		return errors.New(jwa.ErrInvalidAlgorithm)
	}

	pub, err := opt.Public()
	if err != nil {
		return err
	}

	if err = jwa.RSAVerify(message, signature, pub, opt.Algorithm); err != nil {
		return errors.New(jwa.ErrAlteredMessage)
	}
	return nil
}
