package jwt

//Header with well known fields
type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

//JWT is the acronym for JSON Web Token that is defined here:
//https://tools.ietf.org/html/rfc7519 (RFC7519)
/*
	This structure represents a JWT, that can be signed (JWS) or encripted (JWE)
	So this struct is the base for the token manipulations.
*/
type JWT struct {
	Header    Header `json:"header"`
	Payload   Claims `json:"payload"`
	Signature []byte `json:"signature"`
}

func (jwt *JWT) Unmarshal(data []byte) error {

}
