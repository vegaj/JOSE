package jws

import (
	"testing"
	"time"

	"github.com/vegaj/JOSE/jwa"
	"github.com/vegaj/JOSE/jwt"
)

func Test_JWS_ES256(t *testing.T) {
	var opt = &Options{
		Algorithm:  jwa.ES256,
		PrivateKey: testP256Key,
		PublicKey:  testP256PubKey,
		SignID:     "pepe",
	}

	var token = jwt.NewJWT()
	token.SetIssuer("pepe")
	token.SetExpirationTime(time.Now().Unix())

	if err := Sign(token, opt); err != nil {
		t.Errorf("Error: %v. %+v", err, token)
	}

	if err := Verify(token, opt); err != nil {
		t.Error(err)
	}
}

func Test_JWS_Foo(t *testing.T) {

	var opt = &Options{
		Algorithm:  jwa.ES256,
		PrivateKey: testP256Key,
		PublicKey:  testP256PubKey,
		SignID:     "pepe",
	}

	msg := []byte("pepeepe")

	if sig, err := EllipticSign(msg, opt); err == nil {
		if err = EllipticVerify(msg, sig, opt); err == nil {
			return
		}
		t.Error(err)
	}

}
