package b64

import (
	"bytes"
	"testing"
)

func Test_B64_NoPadding(t *testing.T) {

	var noPadding = []byte("abc") //is encoded as `YWJj` with 0 padding

	l := len(noPadding)
	v := EncodeURL(noPadding)
	t.Log(v, l)

	data := DecodeURL(EncodeURL(noPadding))

	if data == nil || !bytes.Equal(noPadding, data) {
		t.Errorf("not equivalent strings: %s / %s", noPadding, data)
	}
}

func Test_B64_DifferentPaddings(t *testing.T) {

	var strl = []string{
		`I`, `AM`, `ABC`,
	}

	for _, s := range strl {
		if data := DecodeURL(EncodeURL([]byte(s))); data == nil {
			t.Errorf("invalid decoding with: %s. Decoded as nil", s)
		}
	}

}
