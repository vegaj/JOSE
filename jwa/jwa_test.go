package jwa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"testing"
)

var (
	testDefaultMessage = []byte(`this is a default message to be signed and verified`)
	testRSAPrivateKey  []byte
	testRSAPublicKey   []byte
	testHMACKey        = randomBytes(16)
)

func TestMain(m *testing.M) {

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	testRSAPrivateKey = x509.MarshalPKCS1PrivateKey(pk)
	testRSAPublicKey = x509.MarshalPKCS1PublicKey(&pk.PublicKey)

	os.Exit(m.Run())
}
