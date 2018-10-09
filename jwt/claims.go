//Package jwt claims information: https://tools.ietf.org/html/rfc7519#section-4
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

//Issuer is the entity that issued this token.
//This is very often application specific.
//OPTIONAL | StringOrURI | 'iss'
func (jwt JWT) Issuer() string {
	return jwt.Payload[issuerk].(string)
}

//SetIssuer is the setter method for this claim.
//Will override any existing one.
func (jwt *JWT) SetIssuer(iss string) {
	jwt.Payload[issuerk] = iss
}

//DelIssuer deletes the previous issuer.
func (jwt *JWT) DelIssuer() {
	delete(jwt.Payload, issuerk)
}

//Subject identifies who is the subject of this JWT.
//It can refers, for example, the user in your sistem that
//this JWT is giving access to, or storing information of.
//The subject value MUST either be scoped to be
//locally unique in the context of the issuer or be globally unique.
//OPTIONAL | StringOrURI | 'sub'
func (jwt JWT) Subject() string {
	return jwt.Payload[subjectk].(string)
}

//SetSubject setter method of this claim
//Will override any existing one.
func (jwt *JWT) SetSubject(sub string) {
	jwt.Payload[subjectk] = sub
}

//DelSubject deletes the previous subject.
func (jwt *JWT) DelSubject() {
	delete(jwt.Payload, subjectk)
}

//Audience identifies the recipients that this JWT is intended for.
//If this JWT is presented to anyone outside of the audience, the JWT
//MUST be discarded.
//  In the general case, the "aud" value is an array of case-
// sensitive strings, each containing a StringOrURI value.
// OPTIONAL | [StringOrURI] | 'aud'
func (jwt JWT) Audience() []string {
	return jwt.Payload[audiencek].([]string)
}

//SetAudience setter method for this claim.
//The new aud will override the previous one.
func (jwt *JWT) SetAudience(aud []string) {
	jwt.Payload[audiencek] = aud
}

//DelAudience delete the previous audience list.
func (jwt *JWT) DelAudience() {
	delete(jwt.Payload, audiencek)
}

//ExpirationTime is the time in which this JWT is no longer
//a valid one and thus, it has to be rejected.
// OPTIONAL | seconds (numeric) | 'exp'
func (jwt JWT) ExpirationTime() int64 {
	return ExtractTimeField(jwt, expirationk)
}

//SetExpirationTime setter method for this claim
func (jwt *JWT) SetExpirationTime(exp int64) {
	jwt.Payload[expirationk] = exp
}

//DelExpirationTime deletes the previous expiration time
func (jwt *JWT) DelExpirationTime() {
	delete(jwt.Payload, expirationk)
}

//NotBefore is the time from which this JWT is valid one.
//If this token is shown before that time, then it must be discarded.
// OPTIONAL | seconds (numeric) | 'nbf'
func (jwt JWT) NotBefore() int64 {
	return ExtractTimeField(jwt, notBeforek)
}

//SetNotBefore setter method for this claim
func (jwt *JWT) SetNotBefore(nbf int64) {
	jwt.Payload[notBeforek] = nbf
}

//DelNotBefore deletes the previous not before timestamp.
func (jwt *JWT) DelNotBefore() {
	delete(jwt.Payload, notBeforek)
}

//IssuedAt is the moment this token was issued by the issuer.
// OPTIONAL | seconds (numeric) | 'iat'
func (jwt JWT) IssuedAt() int64 {
	return ExtractTimeField(jwt, issuedAtk)
}

//SetIssuedAt setter method for this claim
func (jwt *JWT) SetIssuedAt(iat int64) {
	jwt.Payload[issuedAtk] = iat
}

//DelIssuedAt deletes the previous issued at timestamp.
func (jwt *JWT) DelIssuedAt() {
	delete(jwt.Payload, issuedAtk)
}

//TokenID is a unique identifier for the token.
//Please, see https://tools.ietf.org/html/rfc7519#section-4.1.7
//for a complete description of this claim.
//OPTIONAL | StringOrURI | 'jti'
func (jwt JWT) TokenID() string {
	return jwt.Payload[tokenIDk].(string)
}

//SetTokenID setter method for this claim
func (jwt *JWT) SetTokenID(jti string) {
	jwt.Payload[tokenIDk] = jti
}

//DelTokenID deletes the previous token ID
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
