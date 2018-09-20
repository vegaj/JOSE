package jws

import (
	"testing"

	"github.com/vegaj/JOSE/jwa"
)

func Test_RSA256_Signature(t *testing.T) {

	opt := NewOptions(
		jwa.RS256,
		testRSAKey,
		testRSAPubKey,
		"rsa-id",
	)

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

	opt := NewOptions(
		jwa.RS384,
		testRSAKey,
		testRSAPubKey,
		"rsa-id",
	)

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

	opt := NewOptions(
		jwa.RS512,
		testRSAKey,
		testRSAPubKey,
		"rsa-id",
	)

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
	opt := NewOptions(
		jwa.RS512,
		testRSAKey,
		testRSAPubKey2,
		"rsa-id",
	)

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

	opt := NewOptions(
		jwa.HS256,
		testRSAKey,
		testRSAPubKey,
		"rsa-id",
	)

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
	opt := NewOptions(
		jwa.RS256,
		nil,
		nil,
		"rsa-id",
	)

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

	opt := NewOptions(
		555555,
		testRSAKey,
		testRSAPubKey,
		"rsa-id",
	)

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

	opt := NewOptions(
		jwa.HS512,
		testRSAKey,
		testRSAPubKey,
		"rsa-id",
	)

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
