package jwa

import (
	"errors"
	"io"
)

const (
	//ErrIllegalIndex means that the given offset is out of bounds.
	ErrIllegalIndex = `the writting index is illegal`
	//ErrInvalidWhence is not SeekStart, SeekCurrent nor SeekEnd.
	ErrInvalidWhence = `reference is not SeekStart, SeekCurrent nor SeekEnd`
	//ErrNoSpace the writer cannot fit the requested data.
	ErrNoSpace = `not enough space`
)

//OctectWriter is a io.WriteSeeker
type OctectWriter struct {
	Data  []byte
	Index int64
}

//RemainingSpace is the number of bytes that can be written into this writer.
func (o OctectWriter) RemainingSpace() int64 {
	return int64(cap(o.Data)) - o.Index
}

//Write up to the remaining space inside OctectWriter from p.
//If p has more space than the remaining inside
func (o *OctectWriter) Write(p []byte) (n int, err error) {

	var space = int64(cap(o.Data)) - o.Index
	var toWrite = space

	if space == 0 {
		return 0, errors.New(ErrNoSpace)
	}

	if int64(len(p)) > space {
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
func (o *OctectWriter) Seek(offset int64, whence int) (int64, error) {

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
