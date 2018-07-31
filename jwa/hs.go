package jwa

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

//HMACSignature supports the hashing algorithms SHA-256/384/512
func HMACSignature(message []byte, key []byte, alg Algorithm) []byte {

	var hashAlg = translateAlgorithm(alg)

	var h hash.Hash
	switch hashAlg {
	case crypto.SHA256:
		h = hmac.New(sha256.New, key)
	case crypto.SHA384:
		h = hmac.New(sha512.New384, key)
	case crypto.SHA512:
		h = hmac.New(sha512.New, key)
	default:
		return nil
	}

	h.Write(message)
	return h.Sum(nil)
}

//HMACVerify supports the hashing algorithms SHA-256/384/512
func HMACVerify(message, signature, key []byte, alg Algorithm) bool {

	var newsign = HMACSignature(message, key, alg)
	if newsign == nil {
		return false
	}

	return bytes.Equal(newsign, signature)
}
