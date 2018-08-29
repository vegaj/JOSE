package jws

import (
	"errors"
	"math/big"

	"github.com/vegaj/JOSE/jwa"
)

//EllipticSign will perform the signature of message with the given options
func EllipticSign(message []byte, opt *Options) (signature []byte, err error) {

	priv, err := opt.Private()
	if err != nil {
		return nil, err
	}

	r, s, err := jwa.EllipticSign(message, priv, opt.Algorithm)
	if err != nil {
		return nil, err
	}

	//The err field will be nil because that check is already performed on jwa.EllipticSign
	signature, err = allocSignature(opt.Algorithm)
	if err != nil {
		return nil, err
	}

	//In this case, we can trust cap(signature) / 2 because we fixed it in allocSignature.
	var space = cap(signature) / 2
	var lower = addPadding(r.Bytes(), space)
	var upper = addPadding(s.Bytes(), space)
	offsetWrite(signature, lower, 0)
	offsetWrite(signature, upper, space)

	return signature, nil
}

//EllipticVerify will verify that message with signed with options produces the signature
func EllipticVerify(message, signature []byte, opt *Options) (err error) {
	r, s := big.NewInt(0), big.NewInt(0)

	var space = octetsLength(opt.Algorithm)
	if space < 0 {
		return errors.New(jwa.ErrInvalidAlgorithm)
	}

	bytesR := removePadding(signature[:space])
	bytesS := removePadding(signature[space:])

	r = r.SetBytes(bytesR)
	s = s.SetBytes(bytesS)

	pub, err := opt.Public()
	if err != nil {
		return err
	}

	err = jwa.EllipticVerify(message, pub, r, s, opt.Algorithm)
	return err

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

func octetsLength(alg jwa.Algorithm) int {
	switch alg {
	case jwa.ES256:
		return jwa.ESP256Octets / 2
	case jwa.ES384:
		return jwa.ESP384Octets / 2
	case jwa.ES512:
		return jwa.ESP521Octets / 2
	default:
		return -1
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
