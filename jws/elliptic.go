package jws

import (
	"encoding/binary"
	"math/big"

	"github.com/vegaj/JOSE/jwa"
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

func ellipticVerify(message, signature, publicKey []byte, alg jwa.Algorithm) error {
	var r, s = big.NewInt(0), big.NewInt(0)

	ow, _ := jwa.NewOctetWriter(alg)
	if _, err := ow.Read(signature); err != nil {
		return err
	}

	r.SetBytes(ow.Data[cap(ow.Data)/2:])
	s.SetBytes(ow.Data[:cap(ow.Data)/2])

	return jwa.EllipticVerify(message, publicKey, r, s, alg)

}
