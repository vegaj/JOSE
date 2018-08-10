package jws

import (
	"bytes"
	"testing"

	"github.com/vegaj/JOSE/jwa"
)

/*
func Test_ECS_Example(t *testing.T) {

	var kid = "my-hs256-signature"

	var opt = Options{
		Algorithm:  jwa.HS256,
		PrivateKey: testMCKey,
		PublicKey:  testMCKey,
		SignID:     kid,
	}

	var token = jwt.NewJWT()
	err := Sign(&token, opt)
	if err != nil {
		t.Fatal(err)
	}
}
*/
func Test_RemoveTrailing(t *testing.T) {

	allZeroes := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	if r := RemoveTrailingZeroes(allZeroes); len(r) != 8 || !bytes.Equal(allZeroes, r) {
		t.Error("failure with allZeroes")
	}

	oneTrail := []byte{1, 2, 0, 0, 1, 0}
	if r := RemoveTrailingZeroes(oneTrail); len(r) != len(oneTrail)-1 {
		t.Error("failure with oneTrail")
	}

	blank := []byte(nil)
	if r := RemoveTrailingZeroes(blank); r != nil {
		t.Error("failure with blank:", blank)
	}

	noZeroes := []byte{1, 2, 3, 4, 5}
	if r := RemoveTrailingZeroes(noZeroes); !bytes.Equal(r, noZeroes) {
		t.Error("Failure with noZeroes")
	}

	oneZero := []byte{0}
	if r := RemoveTrailingZeroes(oneZero); !bytes.Equal(oneZero, r) {
		t.Error("Failure with oneZero")
	}

	zeroElems := []byte{}
	if r := RemoveTrailingZeroes(zeroElems); len(r) != 0 {
		t.Error("Failure on zeroElems")
	}

	allZeroesButTheLastOne := []byte{0, 0, 0, 0, 0, 0, 0, 0, 1}
	if r := RemoveTrailingZeroes(allZeroesButTheLastOne); !bytes.Equal(r, allZeroesButTheLastOne) {
		t.Error("Failure on allZeroesButTheLastOne")
	}
}

func Test_ECS_SignVerification(t *testing.T) {

	var opt = Options{
		Algorithm:  jwa.ES256,
		PrivateKey: testP224Key,
		PublicKey:  testP224PubKey,
		SignID:     "my-id",
	}
	var msg = []byte("this is my message. What were you expecting, a real jws?")
	signature, err := ellipticSign(msg, &opt)
	if err != nil {
		t.Fatal(err)
	}

	if err = ellipticVerify(msg, signature, &opt); err != nil {
		t.Fatal(err)
	}
}

func Test_P256_Basic(t *testing.T) {
	message := []byte("this is my message")
	opt := &Options{Algorithm: jwa.ES256, PrivateKey: testP224Key, PublicKey: testP224PubKey, SignID: "this-id"}
	sig, err := ellipticSign(message, opt)
	if err != nil {
		t.Fatal(err)
	}

	if err = ellipticVerify(message, sig, opt); err != nil {
		t.Fatal(err)
	}
}

func Test_P384_Basic(t *testing.T) {
	message := []byte("this is my message")
	opt := &Options{Algorithm: jwa.ES384, PrivateKey: testP384Key, PublicKey: testP384PubKey, SignID: "this-id"}
	sig, err := ellipticSign(message, opt)
	if err != nil {
		t.Fatal(err)
	}

	if err = ellipticVerify(message, sig, opt); err != nil {
		t.Fatal(err)
	}
}

func Test_P521_Basic(t *testing.T) {
	message := []byte("this is my message")
	opt := &Options{Algorithm: jwa.ES512, PrivateKey: testP521Key, PublicKey: testP521PubKey, SignID: "this-id"}
	sig, err := ellipticSign(message, opt)
	if err != nil {
		t.Fatal(err)
	}

	if err = ellipticVerify(message, sig, opt); err != nil {
		t.Error(err)
	}

}
