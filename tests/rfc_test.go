package jwa

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/vegaj/JOSE/jwa"

	"github.com/vegaj/JOSE/b64"
)

func Test_RFC_A11(t *testing.T) {

	headerOctets := []byte{123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32, 34, 97, 108, 103, 34, 58, 34, 72, 83, 50, 53, 54, 34, 125}

	expB64Header := `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9`
	b64Header := b64.EncodeURL(headerOctets)
	if expB64Header != b64Header {
		t.Errorf("Different Base64 URL safe encoding for the header.\nF: %s\nE: %s", b64Header, expB64Header)
	}

	payloadOctets := []byte{123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10,
		32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56,
		48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97,
		109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111,
		111, 116, 34, 58, 116, 114, 117, 101, 125}
	expPayload64 := `eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ`

	b64Payload := b64.EncodeURL(payloadOctets)
	if b64Payload != expPayload64 {
		t.Errorf("Different Base64 URL safe encoding for the payload.\nF: %s\nE: %s", b64Header, expB64Header)
	}

	//k (key value) parameter at https://tools.ietf.org/html/rfc7518#section-6.4.1
	/*
		The "k" (key value) parameter contains the value of the symmetric (or
		other single-valued) key.  It is represented as the base64url
		encoding of the octet sequence containing the key value.
	*/
	HMACKey := b64.DecodeURL(`AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow`)

	message := []byte(b64Header + "." + b64Payload)
	expMessage := []byte{101, 121, 74, 48, 101, 88, 65, 105, 79, 105, 74, 75, 86, 49, 81,
		105, 76, 65, 48, 75, 73, 67, 74, 104, 98, 71, 99, 105, 79, 105, 74,
		73, 85, 122, 73, 49, 78, 105, 74, 57, 46, 101, 121, 74, 112, 99, 51,
		77, 105, 79, 105, 74, 113, 98, 50, 85, 105, 76, 65, 48, 75, 73, 67,
		74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65, 52, 77, 84,
		107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100,
		72, 65, 54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76,
		109, 78, 118, 98, 83, 57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73,
		106, 112, 48, 99, 110, 86, 108, 102, 81}
	if !bytes.Equal(message, expMessage) {
		t.Errorf("Different message concatenation\n%v\n%v", message, expMessage)
	}

	sign := jwa.HMACSignature(message, HMACKey, jwa.HS256)
	expSignature := []byte{116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
		187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121}

	if !bytes.Equal(sign, expSignature) {
		t.Errorf("Different signatures: \n%v\n%v", sign, expSignature)
	}

	exp64Signature := `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`
	b64Signature := b64.EncodeURL(sign)
	if exp64Signature != b64Signature {
		t.Errorf("Different b64 signatures:\n%v\n%v", b64Signature, exp64Signature)
	}

	expCompactToken := `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`
	compactToken := string(message) + "." + b64Signature
	if compactToken != expCompactToken {
		t.Errorf("Different final tokens:\n%v\n%v", compactToken, expCompactToken)
	}
}

func Test_ECDSA_512(t *testing.T) {

	headerJSON := []byte{123, 34, 97, 108, 103, 34, 58, 34, 69, 83, 53, 49, 50, 34, 125}
	headerURL := b64.EncodeURL(headerJSON)

	if headerURL != `eyJhbGciOiJFUzUxMiJ9` {
		t.Errorf("Invalid b64 encoding for header")
	}

	payload := []byte{80, 97, 121, 108, 111, 97, 100}
	payloadURL := b64.EncodeURL(payload)
	if payloadURL != `UGF5bG9hZA` {
		t.Errorf("Invalid b64 encoding for payload")
	}

	message := headerURL + "." + payloadURL
	if message != `eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA` {
		t.Errorf("Invalid message")
	}

	var asciiMsg = []byte(message)

	if !bytes.Equal(asciiMsg, []byte{101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 70, 85, 122, 85,
		120, 77, 105, 74, 57, 46, 85, 71, 70, 53, 98, 71, 57, 104, 90, 65}) {
		t.Errorf("Invalid message")
	}

	var key ecdsa.PrivateKey
	key.D = big.NewInt(0).SetBytes(b64.DecodeURL(`AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C`))
	key.PublicKey.Curve = elliptic.P521()
	key.PublicKey.X = big.NewInt(0).SetBytes(b64.DecodeURL(`AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk`))
	key.PublicKey.Y = big.NewInt(0).SetBytes(b64.DecodeURL(`ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2`))

	r, s, err := jwa.EllipticSign(asciiMsg, &key, jwa.ES512)
	if err != nil {
		t.Error(err)
	}

	signature := append(r.Bytes(), s.Bytes()...)

	nr, ns := big.NewInt(0).SetBytes(signature[:jwa.ESP521Octets/2]), big.NewInt(0).SetBytes(signature[jwa.ESP521Octets/2:])
	if err := jwa.EllipticVerify(asciiMsg, &key.PublicKey, nr, ns, jwa.ES512); err != nil {
		t.Error(err)
	}
}
