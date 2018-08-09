package jws

import (
	"errors"
	"math/big"

	"github.com/vegaj/JOSE/jwa"
)

/*
func ellipticSign(message []byte, opt *Options) (signature []byte, err error) {

	r, s, err := jwa.EllipticSign(message, opt.SignWith(), opt.Algorithm)
	if err != nil {
		return nil, err
	}

	ow, err := jwa.NewOctetWriter(opt.Algorithm)
	if err != nil {
		return nil, err
	}

	if err = ow.WriteNumber(r); err != nil {
		return nil, err
	}

	if err = ow.WriteNumber(s); err != nil {
		return nil, err
	}

	return ow.Data, nil
}
*/

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
	var lower = fillBytes(r.Bytes(), space)
	var upper = fillBytes(s.Bytes(), space)
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
	case jwa.EC256:
		return make([]byte, jwa.ECP256Octets, jwa.ECP256Octets), nil
	case jwa.EC384:
		return make([]byte, jwa.ECP384Octets, jwa.ECP384Octets), nil
	case jwa.EC521:
		return make([]byte, jwa.ECP521Octets, jwa.ECP521Octets), nil
	default:
		return nil, errors.New(jwa.ErrInvalidAlgorithm)
	}
}

func fillBytes(src []byte, capacity int) []byte {

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
	/*
		ow, _ := jwa.NewOctetWriter(opt.Algorithm)
		if _, err := ow.Read(signature); err != nil {
			return err
		}
	*/

	var space = cap(signature) / 2
	r = r.SetBytes(signature[:space])
	s = s.SetBytes(signature[space:])

	err = jwa.EllipticVerify(message, opt.VerifyWith(), r, s, opt.Algorithm)
	return err

}
