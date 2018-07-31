package jwa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func Test_RSA_CompleteProcedure(t *testing.T) {

	pk, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	privateKey := x509.MarshalPKCS1PrivateKey(pk)
	publicKey := x509.MarshalPKCS1PublicKey(&pk.PublicKey)

	message := []byte("Fido is my friend. Poor fido.")
	signature, err := RSASign(message, privateKey, RS256)
	if err != nil {
		t.Fatalf("Signature failed: %v", err)
	}

	if err = RSAVerify(message, signature, publicKey, RS256); err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
}

func Test_RSA256_SignVerify(t *testing.T) {

	sign, err := RSASign(testDefaultMessage, testRSAPrivateKey, RS256)
	if err != nil {
		t.Fatal(err)
	}

	err = RSAVerify(testDefaultMessage, sign, testRSAPublicKey, RS256)
	if err != nil {
		t.Fatal(err)
	}

}

func Test_RSA384_SignVerify(t *testing.T) {

	sign, err := RSASign(testDefaultMessage, testRSAPrivateKey, RS384)
	if err != nil {
		t.Fatal(err)
	}

	err = RSAVerify(testDefaultMessage, sign, testRSAPublicKey, RS384)
	if err != nil {
		t.Fatal(err)
	}

}

func Test_RSA512_SignVerify(t *testing.T) {

	sign, err := RSASign(testDefaultMessage, testRSAPrivateKey, RS512)
	if err != nil {
		t.Fatal(err)
	}

	err = RSAVerify(testDefaultMessage, sign, testRSAPublicKey, RS512)
	if err != nil {
		t.Fatal(err)
	}

}
