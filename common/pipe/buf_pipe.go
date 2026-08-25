// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Pipe adapter to connect code expecting an io.Reader
// with code expecting an io.Writer.

package pipe

import (
	"bytes"
	"io"
	"os"
	"sync"
	"time"
)

// A pipe is the shared pipe structure underlying PipeBufferReader and PipeNonblockingWriter.
type pipeBuffer struct {
	wrMu sync.Mutex // Serializes Read operations
	wrCh chan []byte
	buf  *bytes.Buffer

	once sync.Once // Protects closing done
	done chan struct{}
	rerr onceError
	werr onceError

	readDeadline  PipeDeadline
	writeDeadline PipeDeadline
}

func (p *pipeBuffer) read(b []byte) (n int, err error) {
	select {
	case <-p.done:
		return 0, p.readCloseError()
	case <-p.readDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
		p.wrMu.Lock()
		defer p.wrMu.Unlock()
	}

	if p.buf.Len() > 0 {
		return p.buf.Read(b)
	}

	select {
	case bw := <-p.wrCh:
		nr := copy(b, bw)
		if nr < len(bw) {
			p.buf.Reset()
			p.buf.Write(bw[nr:])
		}
		return nr, nil
	case <-p.done:
		return 0, p.readCloseError()
	case <-p.readDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	}
}

func (p *pipeBuffer) closeRead(err error) error {
	if err == nil {
		err = io.ErrClosedPipe
	}
	p.rerr.Store(err)
	p.close()
	return nil
}

func (p *pipeBuffer) write(b []byte) (n int, err error) {
	select {
	case <-p.done:
		return 0, p.writeCloseError()
	case <-p.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}

	select {
	case p.wrCh <- b:
		n = len(b)
	case <-p.done:
		return n, p.writeCloseError()
	case <-p.writeDeadline.Wait():
		return n, os.ErrDeadlineExceeded
	}
	return n, nil
}

func (p *pipeBuffer) closeWrite(err error) error {
	if err == nil {
		err = io.EOF
	}
	p.werr.Store(err)
	p.close()
	return nil
}

// readCloseError is considered internal to the pipe type.
func (p *pipeBuffer) readCloseError() error {
	rerr := p.rerr.Load()
	if werr := p.werr.Load(); rerr == nil && werr != nil {
		return werr
	}
	return io.ErrClosedPipe
}

// writeCloseError is considered internal to the pipe type.
func (p *pipeBuffer) writeCloseError() error {
	werr := p.werr.Load()
	if rerr := p.rerr.Load(); werr == nil && rerr != nil {
		return rerr
	}
	return io.ErrClosedPipe
}

func (p *pipeBuffer) close() {
	p.once.Do(func() {
		close(p.done)
		<-p.done
		close(p.wrCh)
		for range p.wrCh {
		}
		p.wrMu.Lock()
		p.buf.Reset()
		p.buf = nil
		p.wrMu.Unlock()
	})
}

// A PipeBufferReader is the read half of a pipe.
type PipeBufferReader struct{ pipeBuffer }

// Read implements the standard Read interface:
// it reads data from the pipe, blocking until a writer
// arrives or the write end is closed.
// If the write end is closed with an error, that error is
// returned as err; otherwise err is EOF.
func (r *PipeBufferReader) Read(data []byte) (n int, err error) {
	return r.read(data)
}

// Close closes the reader; subsequent writes to
// write half of the pipe will return the error [ErrClosedPipe].
func (r *PipeBufferReader) Close() error {
	return r.CloseWithError(nil)
}

// CloseWithError closes the reader; subsequent writes
// to write half of the pipe will return the error err.
//
// CloseWithError never overwrites the previous error if it exists
// and always returns nil.
func (r *PipeBufferReader) CloseWithError(err error) error {
	return r.closeRead(err)
}

func (r *PipeBufferReader) SetReadDeadline(t time.Time) error {
	if isClosedChan(r.done) {
		return io.ErrClosedPipe
	}
	r.readDeadline.Set(t)
	return nil
}

// A PipeNonblockingWriter is to write half of a pipe.
type PipeNonblockingWriter struct{ r PipeBufferReader }

// Write implements the standard Write interface:
// it writes data to the pipe, it's nonblocking writer.
// If the read end is closed with an error, that err is
// returned as err; otherwise err is [ErrClosedPipe].
func (w *PipeNonblockingWriter) Write(data []byte) (n int, err error) {
	return w.r.write(data)
}

// Close closes the writer; subsequent reads from the
// read half of the pipe will return no bytes and EOF.
func (w *PipeNonblockingWriter) Close() error {
	return w.CloseWithError(nil)
}

// CloseWithError closes the writer; subsequent reads from the
// read half of the pipe will return no bytes and the error err,
// or EOF if err is nil.
//
// CloseWithError never overwrites the previous error if it exists
// and always returns nil.
func (w *PipeNonblockingWriter) CloseWithError(err error) error {
	return w.r.closeWrite(err)
}

func (w *PipeNonblockingWriter) SetWriteDeadline(t time.Time) error {
	if isClosedChan(w.r.done) {
		return io.ErrClosedPipe
	}
	w.r.writeDeadline.Set(t)
	return nil
}

// BufferPipe creates a synchronous in-memory pipe.
// It can be used to connect code expecting an [io.Reader]
// with code expecting an [io.Writer].
//
// The [PipeNonblockingWriter] is the nonblocking writer, the [PipeBufferReader] has an internal buffering.
//
// The bufSize is initialized with the [PipeNonblockingWriter] channel's buffer capacity. If channel is full,
// the [PipeNonblockingWriter] will still block, until the reader have read or the pipe is closed.
//
// It is safe to call Read and Write in parallel with each other or with Close.
// Parallel calls to Read and parallel calls to Write are also safe:
// the individual calls will be gated sequentially.
//
// Added SetReadDeadline and SetWriteDeadline methods based on `io.Pipe`.
func BufferPipe(bufSize int) (*PipeBufferReader, *PipeNonblockingWriter) {
	pw := &PipeNonblockingWriter{r: PipeBufferReader{pipeBuffer: pipeBuffer{
		wrCh:          make(chan []byte, max(bufSize, 2)),
		done:          make(chan struct{}),
		buf:           new(bytes.Buffer),
		readDeadline:  MakePipeDeadline(),
		writeDeadline: MakePipeDeadline(),
	}}}
	return &pw.r, pw
}
