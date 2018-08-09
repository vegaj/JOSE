package jws

import (
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

func Test_ECS_SignVerification(t *testing.T) {

	var opt = Options{
		Algorithm:  jwa.EC256,
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
	opt := &Options{Algorithm: jwa.EC256, PrivateKey: testP224Key, PublicKey: testP224PubKey, SignID: "this-id"}
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
	opt := &Options{Algorithm: jwa.EC384, PrivateKey: testP384Key, PublicKey: testP384PubKey, SignID: "this-id"}
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
	opt := &Options{Algorithm: jwa.EC521, PrivateKey: testP521Key, PublicKey: testP521PubKey, SignID: "this-id"}
	sig, err := ellipticSign(message, opt)
	if err != nil {
		t.Fatal(err)
	}

	if err = ellipticVerify(message, sig, opt); err != nil {
		t.Error(err)
	}

}
