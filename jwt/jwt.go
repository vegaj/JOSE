package jwt

import (
	"encoding/json"
	"errors"

	"github.com/vegaj/JOSE/b64"
)

//JWT is the acronym for JSON Web Token that is defined here:
//https://tools.ietf.org/html/rfc7519 (RFC7519)
/*
	This structure represents a JWT, that can be signed (JWS) or encripted (JWE)
	So this struct is the base for the token manipulations.
*/
type JWT struct {
	Header     map[string]interface{} `json:"headers"`
	Payload    Claims                 `json:"payload"`
	Signatures []Signature            `json:"signatures"`
}

//Signature struct contains a JWE header the signature / MAC algorithm used,
//a signature identifier (in order to know for example wich validation key use)
//and many other fields defined here: https://tools.ietf.org/html/rfc7515#section-4
type Signature struct {
	Header    map[string]interface{} `json:"header"`
	Protected string                 `json:"protected"`
	Signature string                 `json:"signature"`
}

//Deserialize returns a new JWT with the information found in data.
//The data is expected to be a compact or a JSON serialization.
func Deserialize(data []byte) (JWT, error) {
	return JWT{}, errors.New("not implemented")
}

//NewJWT will create an empty JWT.
func NewJWT() *JWT {
	return &JWT{
		Header:     make(map[string]interface{}),
		Payload:    make(Claims),
		Signatures: make([]Signature, 0),
	}
}

//CompactSerialization will returns a serialization of the current jwt.
//This serialization will be in the form of:
//<HEADER>.<PAYLOAD> if it's a not signed JWT.
//<HEADER>.<PAYLOAD>.<SIGNATURE> if it's a JWS.
//TODO add support for JWE.
func (jwt JWT) CompactSerialization() ([]byte, error) {

	var signature *Signature
	if len(jwt.Signatures) > 0 {
		signature = &jwt.Signatures[0]
		//TODO We must actually combine both headers.
		jwt.Header["alg"] = signature.Header["alg"]
		jwt.Header["kid"] = signature.Header["kid"]
	} else {
		signature = nil
	}

	headerJSON, err := json.Marshal(jwt.Header)
	if err != nil {
		return nil, err
	}
	payloadJSON, err := json.Marshal(jwt.Payload)
	if err != nil {
		return nil, err
	}

	header64 := b64.EncodeURL(headerJSON)
	payload64 := b64.EncodeURL(payloadJSON)

	var message string

	if signature == nil {
		message = header64 + "." + payload64
	} else {
		message = header64 + "." + payload64 + "." + signature.Signature
	}

	return []byte(message), nil
}

//JSONSerialization returns a transmisible and storable representation of
//this object in JSON format. This serialization is described:
//Here in the case of a JWS: https://tools.ietf.org/html/rfc7515#section-7.2
func (jwt JWT) JSONSerialization() ([]byte, error) {
	return nil, errors.New("not implemented")
}

//JSONFlatSerialization is used as a lighter weight JSON representation for a JWT.
//This representation allows only one signature.
//It's described here: https://tools.ietf.org/html/rfc7515#section-7.2.2
func (jwt JWT) JSONFlatSerialization() ([]byte, error) {
	return nil, errors.New("not implemented")
}
