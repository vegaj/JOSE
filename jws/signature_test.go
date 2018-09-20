package jws

import (
	"testing"
	"time"

	"github.com/vegaj/JOSE/jwa"
	"github.com/vegaj/JOSE/jwt"
)

func Test_JWS_MultiSignature(t *testing.T) {
	var opt = BlankOptions()
	opt.Algorithm = jwa.ES256
	opt.SignID = "elliptic-signnature"
	opt.LoadPrivateKey(testP256Key)
	opt.LoadPublicKey(testP256PubKey)

	var opt2 = BlankOptions()
	opt2.Algorithm = jwa.RS256
	opt2.LoadPrivateKey(testRSAKey)
	opt2.LoadPublicKey(testRSAPubKey)
	opt2.SignID = "rsa-signature"

	var opt3 = BlankOptions()
	opt3.Algorithm = jwa.ES512
	opt3.LoadPrivateKey(testP521Key)
	opt3.LoadPublicKey(testP521PubKey)
	opt3.SignID = "es512-signature"

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
	var opt = BlankOptions()
	opt.Algorithm = jwa.ES256
	opt.LoadPrivateKey(testP256Key)
	opt.LoadPublicKey(testP256PubKey)
	opt.SignID = "pepe"

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

	var opt = BlankOptions()
	opt.Algorithm = jwa.ES384
	opt.SignID = "pepe"
	opt.LoadPrivateKey(testP384Key)
	opt.LoadPublicKey(testP384PubKey)

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

	var opt = BlankOptions()
	opt.Algorithm = jwa.ES512
	opt.SignID = "pepe"
	opt.LoadPrivateKey(testP521Key)
	opt.LoadPublicKey(testP521PubKey)

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

	var opt = BlankOptions()
	opt.Algorithm = jwa.RS256
	opt.SignID = "pepe-rsa"
	opt.LoadPrivateKey(testRSAKey)
	opt.LoadPublicKey(testRSAPubKey)

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

	var opt = BlankOptions()
	opt.Algorithm = jwa.ES256
	opt.SignID = "fido"
	opt.LoadPrivateKey(testP384Key)
	opt.LoadPublicKey(testP256Key)

	token := jwt.NewJWT()
	token.SetIssuer("fido")

	if err := Sign(token, opt); err == nil {
		t.Error("error missed")
	} else if err.Error() != jwa.ErrInvalidCurve {
		t.Errorf("Expected %s, found %v", jwa.ErrInvalidCurve, err)
	}
}

func Test_JWS_SameSignID(t *testing.T) {

	var opt = BlankOptions()
	opt.Algorithm = jwa.RS256
	opt.SignID = "rsa"
	opt.LoadPrivateKey(testRSAKey)
	opt.LoadPublicKey(testRSAPubKey)

	var opt2 = BlankOptions()
	opt2.Algorithm = jwa.RS256
	opt2.SignID = "rsa"
	opt2.LoadPrivateKey(testRSAKey2)
	opt2.LoadPublicKey(testRSAPubKey2)

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

func Test_JWS_Integrity(t *testing.T) {
	var id1, id2 = "pepe", "fido"

	var opt1, opt2 = BlankOptions(), BlankOptions()
	opt1.Algorithm = jwa.RS512
	opt1.SignID = id1
	opt1.LoadPrivateKey(testRSAKey)
	opt1.LoadPublicKey(testRSAPubKey)

	opt2.Algorithm = jwa.RS384
	opt2.SignID = id2
	opt2.LoadPrivateKey(testRSAKey2)
	opt2.LoadPublicKey(testRSAPubKey2)

	var token = jwt.NewJWT()

	if err := Sign(token, opt1); err != nil {
		t.Error(err)
	}

	if err := Sign(token, opt2); err != nil {
		t.Error(err)
	}

	if len(token.Signatures) != 2 {
		t.Fatalf("There must be %d signatures, found: %v", 2, token.Signatures)
	}

	if token.Signatures[0].Header["kid"] != id1 {
		t.Error("invalid id")
	}

	if token.Signatures[1].Header["kid"] != id2 {
		t.Error("invalid id")
	}

}
