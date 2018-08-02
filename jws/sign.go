package jws

import (
	"errors"

	"github.com/vegaj/JOSE/jwa"
	"github.com/vegaj/JOSE/jwt"
)

//Options to perform a signature.
type Options struct {
	SignID     string //This will fill the 'kid' field.
	Algorithm  jwa.Algorithm
	PrivateKey []byte
	PublicKey  []byte
}

//Sign will sign the input JWT according to opt.
func Sign(j *jwt.JWT, opt Options) error {
	j.Signatures = []jwt.Signature{
		jwt.Signature{
			Header: map[string]interface{}{
				"alg": "HS256",
				"kid": "expeditor.com",
			}, Protected: "this is the header below with a HS256 signature",
			Signature: "this is the payload with a HS256 signature",
		}, jwt.Signature{
			Header: map[string]interface{}{
				"alg": "EC521",
				"kid": "somebody-you-can-trust",
			},
			Protected: "this is the header below with a EC521 signature",
			Signature: "this is the payload with a EC521 signature",
		},
	}
	return errors.New("not implemented")
}
