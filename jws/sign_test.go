package jws

import (
	"testing"
	"time"

	"github.com/vegaj/JOSE/jwa"
	"github.com/vegaj/JOSE/jwt"
)

func Test_JWS_MultiSignature(t *testing.T) {
	var opt = &Options{
		Algorithm:  jwa.ES256,
		PrivateKey: testP256Key,
		PublicKey:  testP256PubKey,
		SignID:     "elliptic-signature",
	}

	var opt2 = &Options{
		Algorithm:  jwa.RS256,
		PrivateKey: testRSAKey,
		PublicKey:  testRSAPubKey,
		SignID:     "rsa-signature",
	}

	var opt3 = &Options{
		Algorithm:  jwa.ES512,
		PrivateKey: testP521Key,
		PublicKey:  testP521PubKey,
		SignID:     "es512-signature",
	}

	var token = jwt.NewJWT()
	token.SetIssuer("pepe")
	token.SetExpirationTime(time.Now().Unix())

	if err := Sign(token, opt); err != nil {
		t.Errorf("Error: %v. %+v", err, token)
	}

	if err := Sign(token, opt2); err != nil {
		t.Errorf("Error: %v. %+v", err, token)
	}

	if err := Sign(token, opt3); err != nil {
		t.Errorf("Error: %v. %+v", err, token)
	}

	if err := Verify(token, opt); err != nil {
		t.Error(err)
	}

	if err := Verify(token, opt3); err != nil {
		t.Error(err)
	}

	if err := Verify(token, opt2); err != nil {
		t.Error(err)
	}
}

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

func Test_JWS_ES384(t *testing.T) {
	var opt = &Options{
		Algorithm:  jwa.ES384,
		PrivateKey: testP384Key,
		PublicKey:  testP384PubKey,
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

func Test_JWS_ES521(t *testing.T) {
	var opt = &Options{
		Algorithm:  jwa.ES512,
		PrivateKey: testP521Key,
		PublicKey:  testP521PubKey,
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

func Test_JWS_RSA256(t *testing.T) {
	var opt = &Options{
		Algorithm:  jwa.RS256,
		PrivateKey: testRSAKey,
		PublicKey:  testRSAPubKey,
		SignID:     "pepe-rsa",
	}

	var token = jwt.NewJWT()
	token.SetIssuer("pepe")

	if err := Sign(token, opt); err != nil {
		t.Error(err)
	}

	if err := Verify(token, opt); err != nil {
		t.Error(err)
	}

}

func Test_JWS_InvalidES256(t *testing.T) {

	var opt = &Options{
		Algorithm:  jwa.ES256,
		PrivateKey: testP384Key,
		PublicKey:  testP256PubKey,
		SignID:     "fido",
	}

	token := jwt.NewJWT()
	token.SetIssuer("fido")

	if err := Sign(token, opt); err == nil {
		t.Error("error missed")
	} else if err.Error() != jwa.ErrInvalidCurve {
		t.Errorf("Expected %s, found %v", jwa.ErrInvalidCurve, err)
	}
}

func Test_JWS_SameSignID(t *testing.T) {

	var opt = &Options{
		Algorithm:  jwa.RS256,
		PrivateKey: testRSAKey,
		PublicKey:  testRSAPubKey,
		SignID:     "rsa",
	}

	var opt2 = &Options{
		Algorithm:  jwa.RS256,
		PrivateKey: testRSAKey2,
		PublicKey:  testRSAPubKey2,
		SignID:     "rsa",
	}

	token := jwt.NewJWT()
	token.SetAudience([]string{"pepe", "fido"})
	if err := Sign(token, opt); err != nil {
		t.Error(err)
	}

	if err := Verify(token, opt2); err == nil {
		t.Error("missed error")
	} else if err.Error() != jwa.ErrAlteredMessage {
		t.Errorf("Expected %s, found %v", jwa.ErrAlteredMessage, err)
	}

	//As there are two signatures with the same id, the first match is taken into consideration.
	//So the one signed with opt can be verified meanwhile the one with opt2 cannot.
	if err := Sign(token, opt2); err != nil {
		t.Error(err)
	}
	if err := Verify(token, opt); err != nil {
		t.Error(err)
	}

	if err := Verify(token, opt2); err == nil {
		t.Error("missed error")
	} else if err.Error() != jwa.ErrAlteredMessage {
		t.Errorf("Expected %s, found %v", jwa.ErrAlteredMessage, err)
	}
}

func Test_JWS_NilCals(t *testing.T) {

	var token *jwt.JWT
	var opt *Options

	if err := Sign(token, opt); err == nil {
		t.Error("missed err")
	} else if err.Error() != jwa.ErrInvalidInput {
		t.Errorf("Expected %s, found %v", jwa.ErrInvalidInput, err)
	}
}
