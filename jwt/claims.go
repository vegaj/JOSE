package jwt

import (
	"encoding/json"
	"log"
)

//Claims are statements made about the subject of this token
//The public claims should be managed with the methods here provided.
//If you want to define new claims, take a look to already registered ones
//at: https://www.iana.org/assignments/jwt/jwt.xhtml before creating new ones.
type Claims map[string]interface{}

const (
	issuerk     = `iss`
	subjectk    = `sub`
	audiencek   = `aud`
	expirationk = `exp`
	notBeforek  = `nbf`
	issuedAtk   = `iat`
	tokenIDk    = `jti`
)

//Issuer
func (jwt JWT) Issuer() string {
	return jwt.Payload[issuerk].(string)
}

//SetIssuer
func (jwt *JWT) SetIssuer(iss string) {
	jwt.Payload[issuerk] = iss
}

//DelIssuer
func (jwt *JWT) DelIssuer() {
	delete(jwt.Payload, issuerk)
}

//Subject
func (jwt JWT) Subject() string {
	return jwt.Payload[subjectk].(string)
}

//SetSubject
func (jwt *JWT) SetSubject(sub string) {
	jwt.Payload[subjectk] = sub
}

//DelSubject
func (jwt *JWT) DelSubject() {
	delete(jwt.Payload, subjectk)
}

//Audience
func (jwt JWT) Audience() []string {
	return jwt.Payload[audiencek].([]string)
}

//SetAudience
func (jwt *JWT) SetAudience(aud []string) {
	jwt.Payload[audiencek] = aud
}

//DelAudience
func (jwt *JWT) DelAudience() {
	delete(jwt.Payload, audiencek)
}

//ExpirationTime
func (jwt JWT) ExpirationTime() int64 {
	return ExtractTimeField(jwt, expirationk)
}

//SetExpirationTime
func (jwt *JWT) SetExpirationTime(exp int64) {
	jwt.Payload[expirationk] = exp
}

//DelExpirationTime
func (jwt *JWT) DelExpirationTime() {
	delete(jwt.Payload, expirationk)
}

//NotBefore
func (jwt JWT) NotBefore() int64 {
	return ExtractTimeField(jwt, notBeforek)
}

//SetNotBefore
func (jwt *JWT) SetNotBefore(nbf int64) {
	jwt.Payload[notBeforek] = nbf
}

//DelNotBefore
func (jwt *JWT) DelNotBefore() {
	delete(jwt.Payload, notBeforek)
}

//IssuedAt
func (jwt JWT) IssuedAt() int64 {
	return ExtractTimeField(jwt, issuedAtk)
}

//SetIssuedAt
func (jwt *JWT) SetIssuedAt(iat int64) {
	jwt.Payload[issuedAtk] = iat
}

//DelIssuedAt
func (jwt *JWT) DelIssuedAt() {
	delete(jwt.Payload, issuedAtk)
}

//TokenID
func (jwt JWT) TokenID() string {
	return jwt.Payload[tokenIDk].(string)
}

//SetTokenID
func (jwt *JWT) SetTokenID(jti string) {
	jwt.Payload[tokenIDk] = jti
}

//DelTokenID
func (jwt *JWT) DelTokenID() {
	delete(jwt.Payload, tokenIDk)
}

//ExtractTimeField will try to decode a Claim named  'key'  from the given jwt.
//If there is not a json.Number or int64 value, zero will be returned
func ExtractTimeField(jwt JWT, key string) int64 {
	if field, ok := jwt.Payload[key].(json.Number); ok {
		var value int64
		var err error
		if value, err = field.Int64(); err == nil {
			return value
		}
		log.Println("Extracting timestamp from", key, "encountered the error", err)

	} else if field, ok := jwt.Payload[key].(int64); ok {
		return field
	}
	log.Println("Extracting timestamp from", key, "no valid timestamp found")
	return 0
}
