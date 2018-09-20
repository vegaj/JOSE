package jws

import (
	"bytes"
	"testing"

	"github.com/vegaj/JOSE/jwa"
)

func Test_RemoveTrailing(t *testing.T) {

	allZeroes := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	if r := removePadding(allZeroes); len(r) != 8 || !bytes.Equal(allZeroes, r) {
		t.Error("failure with allZeroes")
	}

	oneTrail := []byte{1, 2, 0, 0, 1, 0}
	if r := removePadding(oneTrail); len(r) != len(oneTrail)-1 {
		t.Error("failure with oneTrail")
	}

	blank := []byte(nil)
	if r := removePadding(blank); r != nil {
		t.Error("failure with blank:", blank)
	}

	noZeroes := []byte{1, 2, 3, 4, 5}
	if r := removePadding(noZeroes); !bytes.Equal(r, noZeroes) {
		t.Error("Failure with noZeroes")
	}

	oneZero := []byte{0}
	if r := removePadding(oneZero); !bytes.Equal(oneZero, r) {
		t.Error("Failure with oneZero")
	}

	zeroElems := []byte{}
	if r := removePadding(zeroElems); len(r) != 0 {
		t.Error("Failure on zeroElems")
	}

	allZeroesButTheLastOne := []byte{0, 0, 0, 0, 0, 0, 0, 0, 1}
	if r := removePadding(allZeroesButTheLastOne); !bytes.Equal(r, allZeroesButTheLastOne) {
		t.Error("Failure on allZeroesButTheLastOne")
	}
}

func Test_ECS_SignVerification(t *testing.T) {

	var opt = NewOptions(jwa.ES256, testP256Key, testP256PubKey, "my-id")
	var msg = []byte("this is my message. What were you expecting, a real jws?")
	signature, err := EllipticSign(msg, opt)
	if err != nil {
		t.Fatal(err)
	}

	if err = EllipticVerify(msg, signature, opt); err != nil {
		t.Fatal(err)
	}
}

func Test_P256_Basic(t *testing.T) {
	message := []byte("this is my message")
	opt := NewOptions(jwa.ES256, testP256Key, testP256PubKey, "this-id")
	sig, err := EllipticSign(message, opt)
	if err != nil {
		t.Fatal(err)
	}

	if err = EllipticVerify(message, sig, opt); err != nil {
		t.Fatal(err)
	}
}

func Test_P384_Basic(t *testing.T) {
	message := []byte("this is my message")
	opt := NewOptions(jwa.ES384, testP384Key, testP384PubKey, "this-id")
	sig, err := EllipticSign(message, opt)
	if err != nil {
		t.Fatal(err)
	}

	if err = EllipticVerify(message, sig, opt); err != nil {
		t.Fatal(err)
	}
}

func Test_P521_Basic(t *testing.T) {
	message := []byte("this is my message")
	opt := NewOptions(jwa.ES512, testP521Key, testP521PubKey, "this-id")
	sig, err := EllipticSign(message, opt)
	if err != nil {
		t.Fatal(err)
	}

	if err = EllipticVerify(message, sig, opt); err != nil {
		t.Error(err)
	}

}

//Consistency Tests

func Test_ECS_WithNoECAlgorithm(t *testing.T) {
	opt := NewOptions(jwa.RS256, testP256Key, testP256PubKey, "fail-id")

	if opt != nil {
		t.Errorf("opt should be nil")
	}
}

func Test_ECS_InvalidAlgorithmKeyPair(t *testing.T) {
	opt := NewOptions(jwa.ES256, testRSAKey, testRSAPubKey, "fail-id")
	if opt != nil {
		t.Errorf("Expected opt to be nil")
	}
}

func Test_ECS_AlgAndKeyDontMatch(t *testing.T) {
	opt := NewOptions(jwa.ES256, testP384Key, testP384PubKey, "fail-id")

	message := []byte("this is my message")
	_, err := EllipticSign(message, opt)
	if err == nil {
		t.Errorf("Error not detected")
	} else if err.Error() != jwa.ErrInvalidCurve {
		t.Errorf("Expected error: %s, found %v", jwa.ErrInvalidCurve, err)
	}
}

//Verification Tests

func Test_ECS_VerifyInvalidAlg(t *testing.T) {
	opt := NewOptions(
		jwa.ES256,
		testP256Key,
		testP256PubKey,
		"fail-id",
	)

	message := []byte("this is my message")
	sig, err := EllipticSign(message, opt)
	if err != nil {
		t.Error("shouldn't had fail.", err)
	}

	opt.Algorithm = jwa.RS256
	err = EllipticVerify(message, sig, opt)
	if err == nil {
		t.Error("Error undetected")
	} else if err.Error() != jwa.ErrInvalidAlgorithm {
		t.Errorf("Expected %s, found  %v", jwa.ErrInvalidAlgorithm, err)
	}

}

func Test_ECS_BlankMessage(t *testing.T) {
	opt := NewOptions(
		jwa.ES256,
		testP256Key,
		testP256PubKey,
		"fail-id",
	)

	message := []byte("")

	sig, err := EllipticSign(message, opt)
	if err != nil {
		t.Error(err)
	}

	if err = EllipticVerify(message, sig, opt); err != nil {
		t.Error(err)
	}
}

func Test_ECS_NilMessage(t *testing.T) {
	opt := NewOptions(
		jwa.ES256,
		testP256Key,
		testP256PubKey,
		"fail-id",
	)

	message := []byte(nil)

	sig, err := EllipticSign(message, opt)
	if err != nil {
		t.Error(err)
	}

	if err = EllipticVerify(message, sig, opt); err != nil {
		t.Error(err)
	}
}

func Test_ECS_BadAlgGoodKeys(t *testing.T) {

	opt := NewOptions(
		jwa.HS256,
		testP256Key,
		testP256PubKey,
		"hi",
	)
	if opt != nil {
		t.Errorf("opt expected to be nil")
	}
}
