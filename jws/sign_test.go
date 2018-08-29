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
