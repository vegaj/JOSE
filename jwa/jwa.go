package jwa

import (
	"math/rand"
)

//Algorithm is the code to indicate wich algorithm you want to use
type Algorithm uint

const (
	//UNSUP is the code for an unsupported algorithm
	UNSUP Algorithm = iota
	//HS256 is the code for HMAC using SHA-256
	HS256
	//HS384 is the code for HMAC using SHA-384
	HS384
	//HS512 is the code for HMAC using SHA-512
	HS512
	//RS256 is the code for RSA using SHA-256
	RS256
	//RS384 is the code for RSA using SHA-384
	RS384
	//RS512 is the code for RSA using SHA-512
	RS512
	//ES256 is the code for elliptic curve P-256 usin SHA-256
	ES256
	//ES384 is the code for elliptic curve P-384 usin SHA-384
	ES384
	//ES512 is the code for elliptic curve P-521 usin SHA-512
	ES512
)

const (
	//HS256Name identifier for HMAC using SHA-256
	HS256Name = `HS256`
	//HS384Name identifier for HMAC using SHA-384
	HS384Name = `HS384`
	//HS512Name identifier for HMAC using SHA-512
	HS512Name = `HS512`
	//RS256Name signature with RSASSA-PKCS1-v1_5 using SHA-256
	RS256Name = `RS256`
	//RS384Name signature with RSASSA-PKCS1-v1_5 using SHA-384
	RS384Name = `RS384`
	//RS512Name signature with RSASSA-PKCS1-v1_5 using SHA-512
	RS512Name = `RS512`

	//ES256Name signature with the elliptic curve P-256 using SHA-256
	ES256Name = `EC256`
	//ES384Name signature with the elliptic curve P-384 using SHA-384
	ES384Name = `EC384`
	//ES512Name signature with the elliptic curve P-521 using SHA-512
	ES512Name = `EC512`

	//ESP256Octets is the required space for signature serialization
	ESP256Octets = 64
	//ESP384Octets is the required space for signature seriaization
	ESP384Octets = 96
	//ESP521Octets is the required space for signature seriaization
	ESP521Octets = 132

	//ECP256Name identifier for Elliptic Curve P-256
	ECP256Name = `P-256`
	//ECP384Name identifier for Elliptic Curve P-256
	ECP384Name = `P-384`
	//ECP521Name identifier for Elliptic Curve P-521
	ECP521Name = `P-521`
)

const (
	//ErrIllegalIndex means that the given offset is out of bounds.
	ErrIllegalIndex = `the writting index is illegal`
	//ErrInvalidWhence is not SeekStart, SeekCurrent nor SeekEnd.
	ErrInvalidWhence = `reference is not SeekStart, SeekCurrent nor SeekEnd`
	//ErrNoSpace the writer cannot fit the requested data.
	ErrNoSpace = `not enough space`
	//ErrInvalidSource means that the input data is not valid
	ErrInvalidSource = `invalid source`
	//ErrInvalidInput means that the arguments for this function were invalid
	ErrInvalidInput = `invalid input`
	//ErrInvalidAlgorithm means that the algorithm provided is not supported or recognized.
	ErrInvalidAlgorithm = `invalid algorithm`
	//ErrInvalidKey means that the given public or private key is invalid
	ErrInvalidKey = `invalid key`
	//ErrAlteredMessage means that the verification failed because the message was altered
	ErrAlteredMessage = `altered message on verification`
	//ErrInvalidCurve means that the given curve is not appropriate in this context.
	//It could be because the curve is not recognized or because a different one was expected.
	ErrInvalidCurve = `invalid curve`
	//ErrInvalidKeyLength means that the used key has an invalid size.
	ErrInvalidKeyLength = `invalid key length`
)

const (
	//RSAMinBitLength is the minimum length that a RSA key can have.
	// A key of size 2048 bits or larger MUST be used with these algorithms.
	//Defined Here: https://tools.ietf.org/html/rfc7518#section-3.3
	RSAMinBitLength = 2048
)

//Signer interface
type Signer interface{ SignWith() []byte }

//Verifier interface
type Verifier interface{ VerifyWith() []byte }

func randomBytes(len int) []byte {
	data := make([]byte, len)

	for i := 0; i < len; i++ {
		data[i] = byte(rand.Intn(8))
	}
	return data
}
