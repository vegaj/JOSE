package jws

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"

	"github.com/vegaj/JOSE/b64"

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

const (
	//ErrSignatureNotFound means that the signature with a certain kid is missing.
	ErrSignatureNotFound = `signature not found`
	//ErrHeaderNotFound means that the signature was expected to have a header, which was found to be malformed or not present.
	ErrHeaderNotFound = `header not found`
)

//Private will try to parse the given PrivateKey.
func (opt *Options) Private() (crypto.PrivateKey, error) {
	if opt.prik == nil {
		pk, err := unmarshalPrivate(opt.Algorithm, opt.PrivateKey)
		if err != nil {
			return nil, errors.New(jwa.ErrInvalidKey)
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
			return nil, errors.New(jwa.ErrInvalidKey)
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
func Sign(j *jwt.JWT, opt *Options) error {

	var err error
	var message []byte

	var signature jwt.Signature

	j.Header["typ"] = "JWS"

	if message, err = createMessage(j); err != nil {
		return err
	}

	signature.Header = make(map[string]interface{})
	signature.Header["alg"] = jwa.GetAlgorithmName(opt.Algorithm)
	signature.Header["kid"] = opt.SignID

	var protected, encodedSignature string

	protectedHeaderJSON, err := json.Marshal(signature.Header)
	if err != nil {
		return err
	}

	switch opt.Algorithm {
	case jwa.HS256, jwa.HS384, jwa.HS512:
		return errors.New("unimplemented")
	case jwa.ES256, jwa.ES384, jwa.ES512:
		//Perform Elliptic Signature
		sig, err := EllipticSign(message, opt)
		if err != nil {
			return err
		}

		prot, err := EllipticSign(protectedHeaderJSON, opt)
		if err != nil {
			return err
		}

		protected = b64.EncodeURL(prot)
		encodedSignature = b64.EncodeURL(sig)

	case jwa.RS256, jwa.RS384, jwa.RS512:
		//Perform RSA signature.
	default:
		return errors.New(jwa.ErrInvalidAlgorithm)
	}

	signature.Protected = protected
	signature.Signature = encodedSignature
	j.Signatures = append(j.Signatures, signature)

	return nil
}

//Verify will ensure that the signature with the same SignID as in opt.
func Verify(j *jwt.JWT, opt *Options) error {

	var err error
	var signature jwt.Signature
	//var signatureHeaderJSON []byte

	signature, err = findTargetSignature(j.Signatures, opt)

	if err != nil {
		return err
	}

	message, err := createMessage(j)
	if err != nil {
		return err
	}

	///var protected = b64.DecodeURL(signature.Protected)
	var sign = b64.DecodeURL(signature.Signature)

	//Header makes sense
	if err = checkHeader(signature.Header, opt); err != nil {
		return err
	}

	/*if signatureHeaderJSON, err = json.Marshal(signature.Header); err != nil {
		return err
	}
	*/
	switch opt.Algorithm {
	case jwa.HS256, jwa.HS384, jwa.HS512:
		return errors.New("unimplemented")
	case jwa.ES256, jwa.ES384, jwa.ES512:

		if err = EllipticVerify(message, sign, opt); err != nil {
			return err
		}

	case jwa.RS256, jwa.RS384, jwa.RS512:
		//Perform RSA verification.
	default:
		return errors.New(jwa.ErrInvalidAlgorithm)
	}

	return nil
}

func createMessage(j *jwt.JWT) ([]byte, error) {
	var err error
	var headerJSON, payloadJSON []byte
	if headerJSON, err = json.Marshal(j.Header); err != nil {
		return nil, err
	}

	if payloadJSON, err = json.Marshal(j.Payload); err != nil {
		return nil, err
	}

	return []byte(b64.EncodeURL(headerJSON) + "." + b64.EncodeURL(payloadJSON)), nil
}

func findTargetSignature(sigs []jwt.Signature, opt *Options) (jwt.Signature, error) {

	if len(sigs) == 0 {
		return jwt.Signature{}, errors.New(ErrSignatureNotFound)
	}

	if len(sigs) == 1 {
		return sigs[0], nil
	}

	for i, v := range sigs {
		if v.Header["kid"] != nil && v.Header["kid"].(string) == opt.SignID {
			return sigs[i], nil
		}
	}

	return jwt.Signature{}, errors.New(ErrSignatureNotFound)
}

func checkHeader(header map[string]interface{}, opt *Options) error {

	if header == nil {
		return errors.New(ErrHeaderNotFound)
	}

	if algName, ok := header["alg"]; ok {
		if alg, ok := algName.(string); ok {
			if jwa.AlgorithmFromName(alg) == opt.Algorithm {
				return nil
			}
			return errors.New(jwa.ErrInvalidAlgorithm)
		}
	}
	return errors.New(ErrHeaderNotFound)
}
