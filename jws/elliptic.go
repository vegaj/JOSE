package jws

import (
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/vegaj/jwt/jwa"
)

func ellipticSign(message []byte, sign jwa.Signer, alg jwa.Algorithm) (signature []byte, err error) {

	r, s, err := jwa.EllipticSign(message, sign.SignWith(), alg)
	if err != nil {
		return nil, err
	}

	ow, err := jwa.NewOctetWriter(alg)
	if err != nil {
		return nil, err
	}

	if err = ow.WriteNumber(r, binary.BigEndian); err != nil {
		return nil, err
	}

	if err = ow.WriteNumber(s, binary.BigEndian); err != nil {
		return nil, err
	}

	return ow.Data, nil
}

func ellipticVerify(message, signature []byte, verify jwa.Verifier, alg jwa.Algorithm) (bool, error) {
	var r, s = big.NewInt(0), big.NewInt(0)
	return false, errors.New("not implemented")
}
