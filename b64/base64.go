package b64

import (
	"encoding/base64"
	"strings"
)

//EncodeURL the data to base64 without padding and url safe
func EncodeURL(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

//DecodeURL base64 adding the possible missing paddinng and back to bytes.
//returns nil on error
func DecodeURL(urlenc string) []byte {

	urlenc = undoTrim(urlenc)
	var err error
	var data []byte
	if data, err = base64.URLEncoding.DecodeString(urlenc); err == nil {
		return data
	}

	if e, ok := err.(base64.CorruptInputError); ok {
		panic(e.Error())
	}

	return nil
}

func undoTrim(str string) string {
	var taken = len(str) % 4
	if taken > 0 {
		res := str + strings.Repeat("=", 4-taken)
		return res
	}
	return str
}
