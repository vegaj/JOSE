package jwa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"log"
	"math/big"
	rnd "math/rand"
)

//Algorithm is the code to indicate wich algorithm you want to use
type Algorithm uint

const (
	//HS256 is the code for HMAC using SHA-256
	HS256 Algorithm = iota
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
	//EC256 is the code for elliptic curve P-256 usin SHA-256
	EC256
	//EC384 is the code for elliptic curve P-384 usin SHA-384
	EC384
	//EC521 is the code for elliptic curve P-521 usin SHA-512
	EC521
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
	//ECP256Name identifier for Elliptic Curve P-256
	ECP256Name = `P-256`
	//ECP384Name identifier for Elliptic Curve P-256
	ECP384Name = `P-384`
	//ECP521Name identifier for Elliptic Curve P-521
	ECP521Name = `P-521`

	//ECP256Octets is the required space for signature serialization
	ECP256Octets = 64
	//ECP384Octets is the required space for signature seriaization
	ECP384Octets = 96
	//ECP521Octets is the required space for signature seriaization
	ECP521Octets = 132
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

//SignES256 Implement it in JSW
func SignES256(message, serializedPrivateKey []byte) (signature []byte, err error) {

	//Create Hash
	hash := sha256.New().Sum(message)

	//Sign with elliptic curve and private key
	var r, s *big.Int
	r, s, err = ECSignature(hash, serializedPrivateKey)
	if err != nil {
		return nil, err
	}

	//Create the token with the encoded form the returned r and s
	ow, _ := NewOctetWriter(ECP256Name) //We ignore the error because we are using constants
	if err := ow.WriteNumber(r, binary.BigEndian); err != nil {
		return nil, err
	}

	if err := ow.WriteNumber(s, binary.BigEndian); err != nil {
		return nil, err
	}
	signature = ow.Data
	return signature, nil
}

//ECSignature Implement it in JSW
func ECSignature(hash, serializedPrivateKey []byte) (r, s *big.Int, err error) {

	zero := big.NewInt(0)
	var privateKey *ecdsa.PrivateKey
	if privateKey, err = x509.ParseECPrivateKey(serializedPrivateKey); err != nil {
		return zero, zero, err
	}

	return ecdsa.Sign(rand.Reader, privateKey, hash)
}

//ECVerify Implement it in JWS
func ECVerify(serializedPublicKey, hash []byte, r, s *big.Int) bool {

	publicKey, err := x509.ParsePKIXPublicKey(serializedPublicKey)
	if err != nil {
		log.Println("EC Verify error <", err, ">")
		return false
	}

	switch publicKey := publicKey.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.Verify(publicKey, hash, r, s)
	default:
		log.Println("EC Verify : not a ecds public key")
		return false
	}
}

func randomBytes(len int) []byte {
	data := make([]byte, len)

	for i := 0; i < len; i++ {
		data[i] = byte(rnd.Intn(8))
	}
	return data
}
