package jwa

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func Test_HMAC256_SignVerify(t *testing.T) {
	signature := HMACSignature(testDefaultMessage, testHMACKey, HS256)

	if !HMACVerify(testDefaultMessage, signature, testHMACKey, HS256) {
		t.Errorf("validation failed.")
	}
}

func Test_HMAC384_SignVerify(t *testing.T) {
	signature := HMACSignature(testDefaultMessage, testHMACKey, HS384)

	if !HMACVerify(testDefaultMessage, signature, testHMACKey, HS384) {
		t.Errorf("validation failed.")
	}
}

func Test_HMAC512_SignVerify(t *testing.T) {
	signature := HMACSignature(testDefaultMessage, testHMACKey, HS512)

	if !HMACVerify(testDefaultMessage, signature, testHMACKey, HS512) {
		t.Errorf("validation failed.")
	}
}

//According to https://www.di-mgt.com.au/sha_testvectors.html
//an empty string possesses a valid hash. This means that an
//empty message can be hashed and signed.
//https://crypto.stackexchange.com/questions/26133/sha-256-hash-of-null-input
func Test_Nil_Hash(t *testing.T) {

	sh := sha256.New()
	_, err := sh.Write(nil)
	if err != nil {
		t.Error(err)
	}

	hash1 := sh.Sum(nil)

	sh2 := sha256.New()
	sh2.Write(nil)
	hash2 := sh2.Sum(nil)

	if !bytes.Equal(hash1, hash2) {
		t.Errorf("Different hashes for the same nil message: %v / %v", hash1, hash2)
	}

}
