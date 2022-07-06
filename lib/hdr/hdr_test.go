package hdr

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHdrParser(t *testing.T) {
	src := `package stub
	
	// bla bla bla
	func k()
	func o(p []byte)
	// func a() uint64
	func b(a, b uint64) 
	// func c(a, b uint64) uint64
	// func p(a uint64, s string) error
	func as(a string)
	// func ms(*string)
	func ms(a *string)
	func ms(a, b *string) (ret unsafe.Pointer)

	func init() {}
	func anotherFnDecl() {
		println("hello")
	}
	`
	hdr, err := ParseFile("", src, "amd64")
	assert.NoError(t, err)
	fns := hdr.GetFuncDecls(false)
	for _, fn := range fns {
		args, rets, sz := hdr.GetFuncArgRetSize(fn)
		fmt.Printf("fn %q %+#v %+#v  %+#v\n\n",
			fn.Name,
			args,
			rets,
			sz)
	}
}
