package jws

import (
	"crypto"
	"crypto/x509"
	"errors"

	"github.com/vegaj/JOSE/jwa"
	"github.com/vegaj/JOSE/jwt"
)

//Options to perform a signature.
type Options struct {
	SignID     string //This will fill the 'kid' field.
	Algorithm  jwa.Algorithm
	PrivateKey []byte
	PublicKey  []byte

	prik crypto.PrivateKey
	pubk crypto.PublicKey
}

//Private will try to parse the given PrivateKey.
func (opt *Options) Private() (crypto.PrivateKey, error) {
	if opt.prik == nil {
		pk, err := unmarshalPrivate(opt.Algorithm, opt.PrivateKey)
		if err != nil {
			return nil, errors.New(jwa.ErrInvalidKeyForAlgorithm)
		}
		opt.prik = pk
	}
	return opt.prik, nil
}

//Public will try to parse the given VerificationKey.
func (opt *Options) Public() (crypto.PublicKey, error) {
	if opt.pubk == nil {
		pk, err := unmarshalPublic(opt.Algorithm, opt.PublicKey)
		if err != nil {
			return nil, errors.New(jwa.ErrInvalidKeyForAlgorithm)
		}
		opt.pubk = pk
	}
	return opt.pubk, nil
}

func unmarshalPrivate(alg jwa.Algorithm, key []byte) (crypto.PrivateKey, error) {
	switch alg {
	case jwa.RS256, jwa.RS384, jwa.RS512:
		return x509.ParsePKCS1PrivateKey(key)
	case jwa.ES256, jwa.ES384, jwa.ES512:
		return x509.ParseECPrivateKey(key)
	case jwa.HS256, jwa.HS384, jwa.HS512:
		return nil, errors.New(jwa.ErrInvalidKey)
	default:
		return nil, errors.New(jwa.ErrInvalidAlgorithm)
	}
}

func unmarshalPublic(alg jwa.Algorithm, key []byte) (crypto.PublicKey, error) {
	switch alg {
	case jwa.RS256, jwa.RS384, jwa.RS512:
		return x509.ParsePKCS1PublicKey(key)
	case jwa.ES256, jwa.ES384, jwa.ES512:
		return x509.ParsePKIXPublicKey(key)
	case jwa.HS256, jwa.HS384, jwa.HS512:
		return nil, errors.New(jwa.ErrInvalidKey)
	default:
		return nil, errors.New(jwa.ErrInvalidAlgorithm)
	}
}

//SignWith implements jwa.Signer
func (opt *Options) SignWith() []byte {
	return opt.PrivateKey
}

//VerifyWith implements jwa.Verifier
func (opt *Options) VerifyWith() []byte {
	return opt.PublicKey
}

//Sign will sign the input JWT according to opt.
func Sign(j *jwt.JWT, opt Options) error {
	j.Signatures = []jwt.Signature{
		jwt.Signature{
			Header: map[string]interface{}{
				"alg": "HS256",
				"kid": "expeditor.com",
			}, Protected: "this is the header below with a HS256 signature",
			Signature: "this is the payload with a HS256 signature",
		}, jwt.Signature{
			Header: map[string]interface{}{
				"alg": "EC521",
				"kid": "somebody-you-can-trust",
			},
			Protected: "this is the header below with a EC521 signature",
			Signature: "this is the payload with a EC521 signature",
		},
	}
	return errors.New("not implemented")
}
