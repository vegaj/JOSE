package jwa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"testing"
)

var (
	testDefaultMessage = []byte(`this is a default message to be signed and verified`)
	testRSAPrivateKey  *rsa.PrivateKey
	testRSAPublicKey   *rsa.PublicKey
	testECPublicKey    *ecdsa.PublicKey
	testECPrivateKey   *ecdsa.PrivateKey
	testHMACKey        = randomBytes(16)
)

func TestMain(m *testing.M) {

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	testRSAPrivateKey = pk
	testRSAPublicKey = &pk.PublicKey

	os.Exit(m.Run())
}
