package jws

import (
	"crypto"
	"crypto/x509"
	"errors"

	"github.com/vegaj/JOSE/jwa"
)

//Options to perform a signature.
type Options struct {
	Algorithm string
	KeySet    DigitalSignatureKeySet
}

//DigitalSignatureKeySet is the interface that gives access to the KeyPairs for Sign/Verify
type DigitalSignatureKeySet interface {
	Public() crypto.PublicKey
	Private() crypto.PrivateKey
}

type digSign struct {
	pk  crypto.PrivateKey
	pub crypto.PublicKey
}

//LoadPrivateKey takes a DER encoded PrivateKey and an algorithm to be used to sign.
//The keys for EllipticCurve must be in the a ASN.1 DER form.
//In the case of RSA only the ASN.1 PKCS#1 DER format is allowed.
func (opt *Options) LoadPrivateKey(alg jwa.Algorithm, privateKey []byte) error {
	var k crypto.PrivateKey
	var err error
	switch alg {
	case jwa.ES256, jwa.ES384, jwa.ES512:
		k, err = x509.ParseECPrivateKey(privateKey)
		if err != nil {
			return err
		}
	case jwa.RS256, jwa.RS384, jwa.RS512:
		k, err = x509.ParsePKCS1PrivateKey(privateKey)
		if err != nil {
			return err
		}
	default:
		errors.New(jwa.ErrInvalidAlgorithm)
	}

	var digs = digSign{
		pk:  k,
		pub: opt.KeySet.Public(),
	}

	opt.KeySet = digs
	return nil
}

//LoadPublicKey takes a DER encoded PublicKey and an algorithm to be used to verify.
//The keys for EC must be an PKIX form.
//In the case of RSA only a ASN.1 PKCS#1 DER public key is allowed.
func (opt *Options) LoadPublicKey(alg jwa.Algorithm, publicKey []byte) error {
	var k crypto.PublicKey
	var err error
	switch alg {
	case jwa.ES256, jwa.ES384, jwa.ES512:
		k, err = x509.ParsePKIXPublicKey(publicKey)
		if err != nil {
			return err
		}
	case jwa.RS256, jwa.RS384, jwa.RS512:
		k, err = x509.ParsePKCS1PublicKey(publicKey)
		if err != nil {
			return err
		}
	default:
		return errors.New(jwa.ErrInvalidAlgorithm)
	}

	var digs = digSign{
		pk:  opt.KeySet.Private(),
		pub: k,
	}

	opt.KeySet = digs
	return nil
}

func (d digSign) Public() crypto.PublicKey {
	return d.pub
}

func (d digSign) Private() crypto.PrivateKey {
	return d.pk
}

//BlankOptions creates a new Option with no settings on it.
func BlankOptions() *Options {
	return &Options{Algorithm: "", KeySet: digSign{}}
}
