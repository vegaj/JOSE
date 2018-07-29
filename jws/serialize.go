package jws

import (
	"encoding/ascii85"

	jwt "github.com/vegaj/jwt/jwt"
)

//SignSettings signature settings
type SignSettings struct {
}

func Compact(token jwt.JWT, settings SignSettings, secret []byte) string {

	//Ignoring settings by now

	ascii85.Encode(result)
	return ""
}
