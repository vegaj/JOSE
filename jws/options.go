package jws

import (
	"crypto"
	"crypto/x509"

	"github.com/vegaj/JOSE/jwa"
)

//Options to perform a signature.
type Options struct {
	Algorithm jwa.Algorithm
	SignID    string
	keySet    DigitalSignatureKeySet
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

//Public implements the DigitalSignatureKeySet interface.
func (opt *Options) Public() crypto.PublicKey {
	if opt.keySet == nil {
		return nil
	}
	return opt.keySet.Public()
}

//Private implements the DigitalSignatureKeySet interface.
func (opt *Options) Private() crypto.PrivateKey {
	if opt.keySet == nil {
		return nil
	}
	return opt.keySet.Private()
}

//LoadPrivateKey takes a DER encoded PrivateKey and an algorithm to be used to sign.
//The keys for EllipticCurve must be in the a ASN.1 DER form.
//In the case of RSA only the ASN.1 PKCS#1 DER format is allowed.
func (opt *Options) LoadPrivateKey(privateKey []byte) *Options {
	var k crypto.PrivateKey
	var err error
	switch opt.Algorithm {
	case jwa.ES256, jwa.ES384, jwa.ES512:
		k, err = x509.ParseECPrivateKey(privateKey)
		if err != nil {
			panic(err)
		}
	case jwa.RS256, jwa.RS384, jwa.RS512:
		k, err = x509.ParsePKCS1PrivateKey(privateKey)
		if err != nil {
			panic(err)
		}
	default:
		panic(jwa.ErrInvalidAlgorithm)
	}

	var digs = digSign{
		pk:  k,
		pub: opt.keySet.Public(),
	}

	opt.keySet = digs
	return opt
}

//LoadPublicKey takes a DER encoded PublicKey and an algorithm to be used to verify.
//The keys for EC must be an PKIX form.
//In the case of RSA only a ASN.1 PKCS#1 DER public key is allowed.
func (opt *Options) LoadPublicKey(publicKey []byte) *Options {
	var k crypto.PublicKey
	var err error
	switch opt.Algorithm {
	case jwa.ES256, jwa.ES384, jwa.ES512:
		k, err = x509.ParsePKIXPublicKey(publicKey)
		if err != nil {
			panic(err)
		}
	case jwa.RS256, jwa.RS384, jwa.RS512:
		k, err = x509.ParsePKCS1PublicKey(publicKey)
		if err != nil {
			panic(err)
		}
	default:
		panic(jwa.ErrInvalidAlgorithm)
	}

	var digs = digSign{
		pk:  opt.keySet.Private(),
		pub: k,
	}

	opt.keySet = digs
	return opt
}

func (d digSign) Public() crypto.PublicKey {
	return d.pub
}

func (d digSign) Private() crypto.PrivateKey {
	return d.pk
}

//BlankOptions creates a new Option with no settings on it.
func BlankOptions() *Options {
	return &Options{keySet: digSign{}}
}

//NewOptions with the given parameters
func NewOptions(alg jwa.Algorithm, priv, pub []byte, signID string) *Options {
	var opt = BlankOptions()
	opt.Algorithm = alg
	opt.SignID = signID
	return opt.LoadPrivateKey(priv).LoadPublicKey(pub)
}
