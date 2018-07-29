package jwa

import (
	"crypto/hmac"
	"crypto/sha256"
)

//HS256 signs the message with the secret
func HS256(message []byte, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	return h.Sum(message)
}

func ES256(message, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)

	//r, s, err := ecdsa.Sign()
	return h.Sum(message)
}
