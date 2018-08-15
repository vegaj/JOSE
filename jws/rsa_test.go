package jws

import (
	"testing"

	"github.com/vegaj/JOSE/jwa"
)

func Test_RSA256_Signature(t *testing.T) {

	opt := &Options{
		Algorithm:  jwa.RS256,
		PrivateKey: testRSAKey,
		PublicKey:  testRSAPubKey,
		SignID:     "rsa-id",
	}

	message := []byte("this is the message")
	signature, err := rsaSignature(message, opt)
	if err != nil {
		t.Fatal(err)
	}

	if err = rsaVerify(message, signature, opt); err != nil {
		t.Fatal(err)
	}
}

func Test_RSA384_Signature(t *testing.T) {

	opt := &Options{
		Algorithm:  jwa.RS384,
		PrivateKey: testRSAKey,
		PublicKey:  testRSAPubKey,
		SignID:     "rsa-id",
	}

	message := []byte("this is the message")
	signature, err := rsaSignature(message, opt)
	if err != nil {
		t.Fatal(err)
	}

	if err = rsaVerify(message, signature, opt); err != nil {
		t.Fatal(err)
	}
}

func Test_RSA512_Signature(t *testing.T) {

	opt := &Options{
		Algorithm:  jwa.RS512,
		PrivateKey: testRSAKey,
		PublicKey:  testRSAPubKey,
		SignID:     "rsa-id",
	}

	message := []byte("this is the message")
	signature, err := rsaSignature(message, opt)
	if err != nil {
		t.Fatal(err)
	}

	if err = rsaVerify(message, signature, opt); err != nil {
		t.Fatal(err)
	}
}

func Test_RSADifferentKeys(t *testing.T) {
	opt := &Options{
		Algorithm:  jwa.RS512,
		PrivateKey: testRSAKey,
		PublicKey:  testRSAPubKey2,
		SignID:     "rsa-id",
	}

	message := []byte("this is the message")
	signature, err := rsaSignature(message, opt)
	if err != nil {
		t.Fatal(err)
	}

	if err = rsaVerify(message, signature, opt); err == nil {
		t.Errorf("Error missed")
	} else if err.Error() != jwa.ErrAlteredMessage {
		t.Errorf("Expected <%s>. Found <%v>", jwa.ErrAlteredMessage, err)
	}
}

func Test_RSA_InvalidAlgorithm(t *testing.T) {

	opt := &Options{
		Algorithm:  jwa.HS256,
		PrivateKey: testRSAKey,
		PublicKey:  testRSAPubKey,
		SignID:     "rsa-id",
	}

	message := []byte("this is the message")
	signature, err := rsaSignature(message, opt)
	if err == nil {
		t.Errorf("Error missed")
	} else if err.Error() != jwa.ErrInvalidAlgorithm {
		t.Errorf("Expected <%s>. Found <%v>", jwa.ErrInvalidAlgorithm, err)
	}

	if err = rsaVerify(message, signature, opt); err == nil {
		t.Errorf("Error missed")
	} else if err.Error() != jwa.ErrInvalidAlgorithm {
		t.Errorf("Expected <%s>. Found <%v>", jwa.ErrInvalidAlgorithm, err)
	}

}

func Test_RSA_NoKeys(t *testing.T) {
	opt := &Options{
		Algorithm:  jwa.RS256,
		PrivateKey: nil,
		PublicKey:  nil,
		SignID:     "rsa-id",
	}

	message := []byte("this is the message")
	signature, err := rsaSignature(message, opt)
	if err == nil {
		t.Errorf("Error missed")
	} else if err.Error() != jwa.ErrInvalidKey {
		t.Errorf("Expected <%s>. Found <%v>", jwa.ErrInvalidKey, err)
	}

	if err = rsaVerify(message, signature, opt); err == nil {
		t.Errorf("Error missed")
	} else if err.Error() != jwa.ErrInvalidKey {
		t.Errorf("Expected <%s>. Found <%v>", jwa.ErrInvalidKey, err)
	}

}

func Test_RSA_MadeUpAlgorithm(t *testing.T) {

	opt := &Options{
		Algorithm:  555555,
		PrivateKey: testRSAKey,
		PublicKey:  testRSAPubKey,
		SignID:     "rsa-id",
	}

	message := []byte("this is the message")
	signature, err := rsaSignature(message, opt)
	if err == nil {
		t.Errorf("Error missed")
	} else if err.Error() != jwa.ErrInvalidAlgorithm {
		t.Errorf("Expected <%s>. Found <%v>", jwa.ErrInvalidAlgorithm, err)
	}

	if err = rsaVerify(message, signature, opt); err == nil {
		t.Errorf("Error missed")
	} else if err.Error() != jwa.ErrInvalidAlgorithm {
		t.Errorf("Expected <%s>. Found <%v>", jwa.ErrInvalidAlgorithm, err)
	}

}

func Test_RSA_MACAlg(t *testing.T) {

	opt := &Options{
		Algorithm:  jwa.HS512,
		PrivateKey: testRSAKey,
		PublicKey:  testRSAPubKey,
		SignID:     "rsa-id",
	}

	message := []byte("this is the message")
	signature, err := rsaSignature(message, opt)
	if err == nil {
		t.Errorf("Error missed")
	} else if err.Error() != jwa.ErrInvalidAlgorithm {
		t.Errorf("Expected <%s>. Found <%v>", jwa.ErrAlteredMessage, err)
	}

	if err = rsaVerify(message, signature, opt); err == nil {
		t.Errorf("Error missed")
	} else if err.Error() != jwa.ErrInvalidAlgorithm {
		t.Errorf("Expected <%s>. Found <%v>", jwa.ErrAlteredMessage, err)
	}

}
