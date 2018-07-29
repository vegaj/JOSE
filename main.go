package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"io"
	"log"
	"math/big"
)

const numberOfOctets = 32

func genPPKeys(random io.Reader) (private_key_bytes, public_key_bytes []byte) {
	private_key, _ := ecdsa.GenerateKey(elliptic.P224(), random)
	private_key_bytes, _ = x509.MarshalECPrivateKey(private_key)
	public_key_bytes, _ = x509.MarshalPKIXPublicKey(&private_key.PublicKey)
	return private_key_bytes, public_key_bytes
}

var originalMsg = "me encanta el fortnite"

func pkSign(hash []byte, private_key_bytes []byte) (r, s *big.Int, err error) {
	zero := big.NewInt(0)
	private_key, err := x509.ParseECPrivateKey(private_key_bytes)
	if err != nil {
		return zero, zero, err
	}

	r, s, err = ecdsa.Sign(rand.Reader, private_key, hash)
	if err != nil {
		return zero, zero, err
	}
	return r, s, nil
}

func Verify(hash, pubKeyBytes []byte, r, s *big.Int) bool {

	publicKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		log.Println("verify raised error", err)
		return false
	}

	switch publicKey := publicKey.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.Verify(publicKey, hash, r, s)
	default:
		return false
	}
}

func main() {

	prkbytes, pukbytes := genPPKeys(rand.Reader)

	hash := sha256.New().Sum([]byte(originalMsg))

	r, s, err := pkSign(hash, prkbytes)
	if err != nil {
		panic(err)
	}

	log.Printf("R: %#v, S: %#v", r, s)

	var rb, sb []byte = make([]byte, numberOfOctets), make([]byte, numberOfOctets)
	var rB, sB = r.Bytes(), s.Bytes()
	for i := 0; i < numberOfOctets; i++ {
		if i < len(rB) {
			rb[i] = rB[i]
		} else {
			rb[i] = 0
		}

		if i < len(sB) {
			sb[i] = sB[i]
		} else {
			sb[i] = 0
		}
	}

	var octets = &Foo{Data: make([]byte, 64), LastRead: 0, LastWrited: 0}

	binary.Write(octets, binary.BigEndian, rb)
	binary.Write(octets, binary.BigEndian, sb)

	log.Println(bytes.Equal(octets.Data[:32], rb))
	log.Println(bytes.Equal(octets.Data[32:], sb))

	bothrs := make([]byte, 64)
	binary.Read(bytes.NewBuffer(octets.Data), binary.BigEndian, bothrs)

	var nr, ns = big.NewInt(0), big.NewInt(0)
	nr.SetBytes(bothrs[:32])
	ns.SetBytes(bothrs[32:])
	log.Println(Verify(hash, pukbytes, nr, ns))
}

//
type Foo struct {
	Data       []byte
	LastWrited int
	LastRead   int
}

type Signature *Foo

func (s *Foo) Write(p []byte) (n int, err error) {

	if s.LastWrited > len(s.Data) {
		s.LastWrited = 0
	}

	if len(p) == 0 {
		return 0, nil
	}

	var i, count = s.LastWrited, 0
	for i = s.LastWrited; i < 64 && count < len(p); i++ {
		s.Data[i] = p[count]
		count++
	}

	s.LastWrited = s.LastWrited + count
	return count, nil
}
