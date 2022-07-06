package proc

import "io"

type Reader struct {
	p *Process
	io.Reader
}

func (r Reader) Read(p []byte) (int, error) {
	return r.Reader.Read(p)
}

type Writer struct {
	p *Process
	io.Writer
}

func (w Writer) Write(p []byte) (int, error) {
	return w.Writer.Write(p)
}
