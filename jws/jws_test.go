package jws

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"testing"
)

//Convertir test***Key de PrivateKey a []byte
var (
	testP256Key, testP256PubKey []byte
	testP384Key, testP384PubKey []byte
	testP521Key, testP521PubKey []byte

	testRSAKey, testRSAPubKey []byte

	testRSAKey2, testRSAPubKey2 []byte

	testMCKey  []byte
	testMCKey2 []byte
)

func TestMain(m *testing.M) {
	if pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err == nil {
		testP256Key, _ = x509.MarshalECPrivateKey(pk)
		testP256PubKey, _ = x509.MarshalPKIXPublicKey(&pk.PublicKey)
	}

	if pk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader); err == nil {
		testP384Key, _ = x509.MarshalECPrivateKey(pk)
		testP384PubKey, _ = x509.MarshalPKIXPublicKey(&pk.PublicKey)
	}

	if pk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader); err == nil {
		testP521Key, _ = x509.MarshalECPrivateKey(pk)
		testP521PubKey, _ = x509.MarshalPKIXPublicKey(&pk.PublicKey)
	}

	if pk, err := rsa.GenerateKey(rand.Reader, 2048); err == nil {
		testRSAKey = x509.MarshalPKCS1PrivateKey(pk)
		testRSAPubKey = x509.MarshalPKCS1PublicKey(&pk.PublicKey)
	}

	if pk, err := rsa.GenerateKey(rand.Reader, 4096); err == nil {
		testRSAKey2 = x509.MarshalPKCS1PrivateKey(pk)
		testRSAPubKey2 = x509.MarshalPKCS1PublicKey(&pk.PublicKey)
	}

	testMCKey = randomBytes(64)
	testMCKey2 = randomBytes(64)

	if bytes.Equal(testMCKey, testMCKey2) {
		panic("same keys")
	}

	os.Exit(m.Run())
}

func randomBytes(len int) []byte {
	data := make([]byte, len)
	rand.Reader.Read(data)
	return data
}
