package main

import (
	"io/ioutil"
	"log"
	"time"

	"github.com/vegaj/JOSE/jwa"

	"github.com/vegaj/JOSE/jws"
	"github.com/vegaj/JOSE/jwt"
)

const (
	fidoSignID = "signature-from-fidoserver"
)

//This is just a demonstration.
//The file will be deleted later on and, perhaps, it will be available in the wiki.
//Please see https://github.com/vegaj/JOSE/wiki for further information.
func main() {

	token := jwt.NewJWT()

	dur, _ := time.ParseDuration("3m")
	validUntil := time.Now().Add(dur)

	token.Header["foo"] = "foo"
	token.SetAudience([]string{"https://api.fidoserver.com/secured/", "https://app.fidoserver.com/dashboard"})
	token.SetExpirationTime(validUntil.Unix())

	var opt = jws.BlankOptions()
	opt.SignID = fidoSignID
	opt.Algorithm = jwa.RS256

	raw, err := ioutil.ReadFile("./keys/keyPub.der")
	if err != nil {
		panic(err)
	}

	if err = opt.LoadPublicKey(raw); err != nil {
		panic(err)
	}

	raw, err = ioutil.ReadFile("./keys/key.der")
	if err != nil {
		panic(err)
	}

	if err = opt.LoadPrivateKey(raw); err != nil {
		panic(err)
	}

	if err = jws.Sign(token, opt); err != nil {
		panic(err)
	}

	log.Printf("Token header:%v.\n\n Token claims:%v\n", token.Header, token.Payload)
	signature := token.Signatures[0]

	log.Printf("There are %d signatures.\n", len(token.Signatures))
	log.Printf("Header:%v\n\nProtected:%v\n\nSignature:%v\n\n", signature.Header, signature.Protected, signature.Signature)

	if err = jws.Verify(token, opt); err != nil {
		log.Println(err)
	} else {
		log.Println("token verified")
	}

	compact, err := token.CompactSerialization()
	if err != nil {
		panic(err)
	}

	//send it to someone, store it as a cookie, so on.
	ioutil.WriteFile("./compactToken.b64", compact, 0)

}
