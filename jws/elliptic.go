package jws

import (
	"errors"
	"math/big"

	"github.com/vegaj/JOSE/jwa"
)

func ellipticSign(message []byte, opt *Options) (signature []byte, err error) {
	r, s, err := jwa.EllipticSign(message, opt.SignWith(), opt.Algorithm)
	if err != nil {
		return nil, err
	}

	signature, err = allocSignature(opt.Algorithm)
	if err != nil {
		return nil, err
	}

	var space = cap(signature) / 2
	var lower = addPadding(r.Bytes(), space)
	var upper = addPadding(s.Bytes(), space)
	offsetWrite(signature, lower, 0)
	offsetWrite(signature, upper, space)

	return signature, nil
}

func offsetWrite(dst, p []byte, offset int) (n int, err error) {

	var space = cap(dst) - offset
	var toWrite = space

	if p == nil {
		return 0, errors.New(jwa.ErrInvalidSource)
	}

	if space == 0 {
		return 0, errors.New(jwa.ErrNoSpace)
	}

	if len(p) < space {
		toWrite = len(p)
	}

	var i int
	for i = 0; i < toWrite; i++ {
		dst[offset+i] = p[i]
	}

	return i, nil
}

func allocSignature(alg jwa.Algorithm) ([]byte, error) {
	switch alg {
	case jwa.ES256:
		return make([]byte, jwa.ESP256Octets, jwa.ESP256Octets), nil
	case jwa.ES384:
		return make([]byte, jwa.ESP384Octets, jwa.ESP384Octets), nil
	case jwa.ES512:
		return make([]byte, jwa.ESP521Octets, jwa.ESP521Octets), nil
	default:
		return nil, errors.New(jwa.ErrInvalidAlgorithm)
	}
}

func addPadding(src []byte, capacity int) []byte {

	data := make([]byte, capacity, capacity)
	for i := 0; i < capacity; i++ {
		if i < len(src) {
			data[i] = src[i]
		} else {
			data[i] = 0
		}
	}

	return data
}

func ellipticVerify(message, signature []byte, opt *Options) (err error) {
	r, s := big.NewInt(0), big.NewInt(0)

	var space = cap(signature) / 2
	r = r.SetBytes(removePadding(signature[:space]))
	s = s.SetBytes(removePadding(signature[space:]))

	err = jwa.EllipticVerify(message, opt.VerifyWith(), r, s, opt.Algorithm)
	return err

}

func removePadding(p []byte) []byte {

	if p == nil {
		return nil
	}

	if len(p) == 0 {
		return p
	}

	index := len(p)

	for i := 0; i < len(p); i++ {
		if p[len(p)-1-i] != 0 {
			return p[:index]
		}
		index--
	}

	return p
}
