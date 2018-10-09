package jwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
)

//ESSignatureWriter is a io.WriteSeeker | DEPRECATED
type ESSignatureWriter struct {
	Data  []byte
	Index int64
}

//NewOctetWriter returns the valid writer for the P-256 Sha-256 digital signature generation
func NewOctetWriter(ESIdentifier Algorithm) (ESSignatureWriter, error) {
	if ESIdentifier == ES256 {
		return ESSignatureWriter{Data: make([]byte, ESP256Octets, ESP256Octets), Index: 0}, nil
	} else if ESIdentifier == ES384 {
		return ESSignatureWriter{Data: make([]byte, ESP384Octets, ESP384Octets), Index: 0}, nil
	} else if ESIdentifier == ES512 {
		return ESSignatureWriter{Data: make([]byte, ESP521Octets, ESP521Octets), Index: 0}, nil
	}
	return ESSignatureWriter{}, errors.New(ErrInvalidAlgorithm)
}

//RemainingSpace is the number of bytes that can be written into this writer.
func (o ESSignatureWriter) RemainingSpace() int64 {
	return int64(cap(o.Data)) - o.Index
}

//Write up to the remaining space inside OctectWriter from p.
//If p has more space than the remaining inside
func (o *ESSignatureWriter) Write(p []byte) (n int, err error) {

	var space = o.RemainingSpace()
	var toWrite = space

	if p == nil {
		return 0, errors.New(ErrInvalidSource)
	}

	if space == 0 {
		return 0, errors.New(ErrNoSpace)
	}

	if int64(len(p)) < space {
		toWrite = int64(len(p))
	}

	var i int64
	for i = 0; i < toWrite; i++ {
		o.Data[o.Index+i] = p[i]
	}

	o.Index += i

	return int(i), nil
}

/*
Seek method implements the io.Seeker interface.
Seek sets the offset for the next Read or Write to offset, interpreted according to whence:
SeekStart means relative to the start of the file, SeekCurrent means relative to the current offset,
and SeekEnd means relative to the end.
Seek returns the new offset relative to the start of the file and an error, if any.
Seeking to an offset before the start of the file is an error.
Seeking to any positive offset is legal, and will be set to
*/
func (o *ESSignatureWriter) Seek(offset int64, whence int) (int64, error) {

	if offset < 0 {
		return int64(o.Index), errors.New(ErrIllegalIndex)
	}

	var position int64
	if io.SeekStart == whence {
		position = offset
	} else if whence == io.SeekCurrent {
		position = offset + o.Index
	} else if whence == io.SeekEnd {
		position = int64(cap(o.Data)) - offset
	} else {
		return o.Index, errors.New(ErrInvalidWhence)
	}

	if position < 0 || position > int64(cap(o.Data)) {
		return o.Index, errors.New(ErrIllegalIndex)
	}

	o.Index = position
	return position, nil
}

//WriteNumber will write the data encoded  binary.Big-Endian.
//As the signature is made out of two big integers, and the whole capacity must be filled.
func (o *ESSignatureWriter) WriteNumber(x *big.Int) error {
	if x == nil {
		return errors.New(ErrInvalidInput)
	}
	return binary.Write(o, binary.BigEndian, fillBytes(x.Bytes(), cap(o.Data)/2))
}

//Reset sets the seeker to the start
func (o *ESSignatureWriter) Reset() {
	o.Index = 0
}

//Read implements io.Reader
func (o *ESSignatureWriter) Read(p []byte) (int, error) {
	rd := bytes.NewReader(p)
	err := binary.Read(rd, binary.BigEndian, o.Data)
	return len(p), err
}

func fillBytes(src []byte, capacity int) []byte {

	data := make([]byte, capacity)
	for i := 0; i < capacity; i++ {
		if i < len(src) {
			data[i] = src[i]
		} else {
			data[i] = 0
		}
	}

	return data
}
