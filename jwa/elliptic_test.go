package jwa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
)

func Test_EC256_SignVerify(t *testing.T) {

	var err error
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Generate ECKey 256: %v", err)
	}

	if testECPrivateKey, err = x509.MarshalECPrivateKey(priv); err != nil {
		t.Fatalf("Marshal private key: %v", err)
	}

	if testECPublicKey, err = x509.MarshalPKIXPublicKey(&priv.PublicKey); err != nil {
		t.Fatalf("Marshal public key: %v", err)
	}

	r, s, err := EllipticSign(testDefaultMessage, testECPrivateKey, EC256)
	if err != nil {
		t.Fatal(err)
	}

	if err = EllipticVerify(testDefaultMessage, testECPublicKey, r, s, EC256); err != nil {
		t.Fatal(err)
	}

}

func Test_EC384_SignVerify(t *testing.T) {

	var err error
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Generate ECKey 384: %v", err)
	}

	if testECPrivateKey, err = x509.MarshalECPrivateKey(priv); err != nil {
		t.Fatalf("Marshal private key: %v", err)
	}

	if testECPublicKey, err = x509.MarshalPKIXPublicKey(&priv.PublicKey); err != nil {
		t.Fatalf("Marshal public key: %v", err)
	}

	r, s, err := EllipticSign(testDefaultMessage, testECPrivateKey, EC384)
	if err != nil {
		t.Fatal(err)
	}

	if err = EllipticVerify(testDefaultMessage, testECPublicKey, r, s, EC384); err != nil {
		t.Fatal(err)
	}

}

func Test_EC521_SignVerify(t *testing.T) {

	var err error
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("Generate ECKey 521: %v", err)
	}

	if testECPrivateKey, err = x509.MarshalECPrivateKey(priv); err != nil {
		t.Fatalf("Marshal private key: %v", err)
	}

	pub := &priv.PublicKey
	if testECPublicKey, err = x509.MarshalPKIXPublicKey(pub); err != nil {
		t.Fatalf("Marshal public key: %v", err)
	}

	r, s, err := EllipticSign(testDefaultMessage, testECPrivateKey, EC521)
	if err != nil {
		t.Fatal(err)
	}

	if err = EllipticVerify(testDefaultMessage, testECPublicKey, r, s, EC521); err != nil {
		t.Fatal(err)
	}

}

//Test_EC256_UsingGreaterCurve. In this case, the key is generated using a curve greater than the expected
//in EC256 wich should be the curve P256 with SHA-256. But this don't fails, because the keys used for signature
//and verification match. The hasing algorithm used is not the expected but it's used consistently.

func Test_EC256_UsingGreaterCurve(t *testing.T) {

	var err error
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Generate ECKey 384: %v", err)
	}

	if testECPrivateKey, err = x509.MarshalECPrivateKey(priv); err != nil {
		t.Fatalf("Marshal private key: %v", err)
	}

	if testECPublicKey, err = x509.MarshalPKIXPublicKey(&priv.PublicKey); err != nil {
		t.Fatalf("Marshal public key: %v", err)
	}

	r, s, err := EllipticSign(testDefaultMessage, testECPrivateKey, EC256)
	if err == nil {
		t.Fatalf("(Sign) nil error, but expecting <%s>", ErrInvalidCurve)
	} else if err.Error() != ErrInvalidCurve {
		t.Errorf("Signature failed but it's due to <%s> instead of <%s>", err.Error(), ErrInvalidCurve)
	}

	//The signature is made out of r and s. So we need them to verify the message has not been altered.
	if err = EllipticVerify(testDefaultMessage, testECPublicKey, r, s, EC256); err == nil {
		t.Fatalf("(Verify) nil error, but expecting <%s>", ErrInvalidCurve)
	} else if err.Error() != ErrInvalidCurve {
		t.Errorf("Verification failed but it's due to <%s> instead of <%s>", err.Error(), ErrInvalidCurve)
	}

}

func Test_EC521_UsingLowerCurve(t *testing.T) {

	var err error
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("Generate ECKey 384: %v", err)
	}

	if testECPrivateKey, err = x509.MarshalECPrivateKey(priv); err != nil {
		t.Fatalf("Marshal private key: %v", err)
	}

	if testECPublicKey, err = x509.MarshalPKIXPublicKey(&priv.PublicKey); err != nil {
		t.Fatalf("Marshal public key: %v", err)
	}

	r, s, err := EllipticSign(testDefaultMessage, testECPrivateKey, EC521)
	if err != nil {
		t.Fatalf("(Sign) Expected a failure because the curves are different, found <%v>", err)
	}

	//The signature is made out of r and s. So we need them to verify the message has not been altered.
	if err = EllipticVerify(testDefaultMessage, testECPublicKey, r, s, EC521); err != nil {
		t.Fatalf("(Verify) Expected a failure because the curves are different, found <%v>", err)
	}

}
