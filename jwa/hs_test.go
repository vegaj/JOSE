package jwa

import "testing"

func Test_HMAC256_SignVerify(t *testing.T) {
	signature := HMACSignature(testDefaultMessage, testHMACKey, HS256)

	if !HMACVerify(testDefaultMessage, signature, testHMACKey, HS256) {
		t.Errorf("validation failed %v.")
	}
}

func Test_HMAC384_SignVerify(t *testing.T) {
	signature := HMACSignature(testDefaultMessage, testHMACKey, HS384)

	if !HMACVerify(testDefaultMessage, signature, testHMACKey, HS384) {
		t.Errorf("validation failed %v.")
	}
}

func Test_HMAC512_SignVerify(t *testing.T) {
	signature := HMACSignature(testDefaultMessage, testHMACKey, HS512)

	if !HMACVerify(testDefaultMessage, signature, testHMACKey, HS512) {
		t.Errorf("validation failed %v.")
	}
}
