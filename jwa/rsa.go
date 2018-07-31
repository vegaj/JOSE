package jwa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"hash"
)

//RSASign signature using the hashing algorithm hashAlg with the given private key.
func RSASign(message, privateKey []byte, alg Algorithm) ([]byte, error) {

	priv, err := x509.ParsePKCS1PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	var hashAlg = translateAlgorithm(alg)

	var hash = doHash(message, hashAlg)
	if hash == nil {
		return nil, errors.New(ErrInvalidAlgorithm)
	}

	return rsa.SignPKCS1v15(rand.Reader, priv, hashAlg, hash)

}

//RSAVerify will return nil if the message with the public key with the hash algorithm generates the given signature.
func RSAVerify(message, signature, publicKey []byte, alg Algorithm) error {

	var hash = translateAlgorithm(alg)

	pub, err := x509.ParsePKCS1PublicKey(publicKey)
	if err != nil {
		return err
	}

	var hashed = doHash(message, hash)

	return rsa.VerifyPKCS1v15(pub, hash, hashed, signature)
}

func translateAlgorithm(alg Algorithm) crypto.Hash {
	switch alg {
	case RS256, HS256:
		return crypto.SHA256
	case RS384, HS384:
		return crypto.SHA384
	case RS512, HS512:
		return crypto.SHA512
	default:
		panic(ErrInvalidAlgorithm)
	}
}

func doHash(message []byte, alg crypto.Hash) []byte {

	var h hash.Hash
	switch alg {
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	default:
		return nil
	}
	h.Write(message)
	return h.Sum(nil)
}
