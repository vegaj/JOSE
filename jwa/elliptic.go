package jwa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"hash"
	"math/big"
)

var zero = big.NewInt(0)

//EllipticSign using ESXXX algorithms.
func EllipticSign(message, privateKey []byte, alg Algorithm) (r, s *big.Int, err error) {

	var pk *ecdsa.PrivateKey
	if pk, err = x509.ParseECPrivateKey(privateKey); err != nil {
		return zero, zero, err
	}

	//If the Algorithm doesn't match the curve, abort.
	if err = curveAndHashMatch(pk.Curve.Params(), alg); err != nil {
		return zero, zero, err
	}

	hash := doHashAlg(message, alg)
	if hash == nil {
		return zero, zero, errors.New(ErrInvalidAlgorithm)
	}

	return ecdsa.Sign(rand.Reader, pk, hash)
}

//EllipticVerify for the ESXXX digital signature algorithms. error = nil means Verification correct.
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

		hash := doHashAlg(message, alg)
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

func doHashAlg(message []byte, alg Algorithm) []byte {
	var hash hash.Hash
	switch alg {
	case ES256:
		hash = sha256.New()
	case ES384:
		hash = sha512.New384()
	case ES512:
		hash = sha512.New()
	default:
		return nil
	}

	hash.Write(message)
	return hash.Sum(nil)
}

//Each ESXXX algorithm has a curve assigned. If the key has a Curve with a name different that
//the one defined in JWA (https://tools.ietf.org/html/rfc7518#section-3.1) then this function
//returns an error with ErrInvalidCurve as message.
func curveAndHashMatch(curveParams *elliptic.CurveParams, alg Algorithm) error {

	var errText = ""
	switch alg {
	case ES256:
		if curveParams.Name != ECP256Name {
			errText = ErrInvalidCurve
		}
	case ES384:
		if curveParams.Name != ECP384Name {
			errText = ErrInvalidCurve
		}
	case ES512:
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
