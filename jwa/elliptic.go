package jwa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"math/big"
)

var zero = big.NewInt(0)

//EllipticSign using ECXXX algorithms.
func EllipticSign(message, privateKey []byte, alg Algorithm) (r, s *big.Int, err error) {

	var pk *ecdsa.PrivateKey
	if pk, err = x509.ParseECPrivateKey(privateKey); err != nil {
		return zero, zero, err
	}

	//If the Algorithm doesn't match the curve, abort.
	if err = curveAndHashMatch(pk.Curve.Params(), alg); err != nil {
		return zero, zero, err
	}

	hash := hashForAlg(message, alg)
	if hash == nil {
		return zero, zero, errors.New(ErrInvalidAlgorithm)
	}

	return ecdsa.Sign(rand.Reader, pk, hash)
}

//EllipticVerify for the ECXXX digital signature algorithms. error = nil means Verification correct.
func EllipticVerify(message, publicKey []byte, r, s *big.Int, alg Algorithm) error {
	pk, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	if pub, ok := pk.(*ecdsa.PublicKey); ok {

		//If the Algorithm doesn't match the curve, abort.
		if err = curveAndHashMatch(pub.Params(), alg); err != nil {
			return err
		}

		hash := hashForAlg(message, alg)
		if hash == nil {
			return errors.New(ErrInvalidAlgorithm)
		}

		if ecdsa.Verify(pub, hash, r, s) {
			return nil
		}
		return errors.New(ErrAlteredMessage)

	}
	return errors.New(ErrInvalidKey)
}

func hashForAlg(message []byte, alg Algorithm) []byte {
	var hash []byte
	switch alg {
	case EC256:
		hash = sha256.New().Sum(message)
	case EC384:
		hash = sha512.New384().Sum(message)
	case EC521:
		hash = sha512.New().Sum(message)
	default:
		return nil
	}
	return hash
}

func curveAndHashMatch(curveParams *elliptic.CurveParams, alg Algorithm) error {

	var errText = ""
	switch alg {
	case EC256:
		if curveParams.Name != ECP256Name {
			errText = ErrInvalidCurve
		}
	case EC384:
		if curveParams.Name != ECP384Name {
			errText = ErrInvalidCurve
		}
	case EC521:
		if curveParams.Name != ECP521Name {
			errText = ErrInvalidCurve
		}
	default:
		errText = ErrInvalidAlgorithm
	}

	if errText == "" {
		return nil
	}
	return errors.New(errText)
}
