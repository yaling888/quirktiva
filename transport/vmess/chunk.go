package vmess

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/yaling888/quirktiva/common/pool"
)

const (
	lenSize   = 2
	chunkSize = 1 << 14   // 2 ** 14 == 16 * 1024
	maxSize   = 17 * 1024 // 2 + chunkSize + aead.Overhead()
)

type chunkReader struct {
	io.Reader
	bufP    *[]byte
	sizeBuf []byte
	offset  int
}

func newChunkReader(reader io.Reader) *chunkReader {
	return &chunkReader{Reader: reader, sizeBuf: make([]byte, lenSize)}
}

func newChunkWriter(writer io.WriteCloser) *chunkWriter {
	return &chunkWriter{Writer: writer}
}

func (cr *chunkReader) Read(b []byte) (int, error) {
	if cr.bufP != nil {
		n := copy(b, (*cr.bufP)[cr.offset:])
		cr.offset += n
		if cr.offset == len(*cr.bufP) {
			pool.PutNetBuf(cr.bufP)
			cr.bufP = nil
		}
		return n, nil
	}

	_, err := io.ReadFull(cr.Reader, cr.sizeBuf)
	if err != nil {
		return 0, err
	}

	size := int(binary.BigEndian.Uint16(cr.sizeBuf))
	if size > maxSize {
		return 0, errors.New("buffer is larger than standard")
	}

	if len(b) >= size {
		_, err := io.ReadFull(cr.Reader, b[:size])
		if err != nil {
			return 0, err
		}

		return size, nil
	}

	bufP := pool.GetNetBuf()
	_, err = io.ReadFull(cr.Reader, (*bufP)[:size])
	if err != nil {
		pool.PutNetBuf(bufP)
		return 0, err
	}
	n := copy(b, (*bufP)[:size])
	*bufP = (*bufP)[:size]
	cr.offset = n
	cr.bufP = bufP
	return n, nil
}

type chunkWriter struct {
	io.Writer
}

func (cw *chunkWriter) Write(b []byte) (n int, err error) {
	bufP := pool.GetNetBuf()
	defer pool.PutNetBuf(bufP)
	length := len(b)
	for {
		if length == 0 {
			break
		}
		readLen := chunkSize
		if length < chunkSize {
			readLen = length
		}
		payloadBuf := (*bufP)[lenSize : lenSize+chunkSize]
		copy(payloadBuf, b[n:n+readLen])

		binary.BigEndian.PutUint16((*bufP)[:lenSize], uint16(readLen))
		_, err = cw.Writer.Write((*bufP)[:lenSize+readLen])
		if err != nil {
			break
		}
		n += readLen
		length -= readLen
	}
	return
}
