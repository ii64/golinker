package disasm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestDisasmARM64(t *testing.T) {
	codes := [][]byte{
		{ // subr
			0xe0, 0x88, 0x9e, 0x52,
			0x00, 0x02, 0xa0, 0x72,
			0xc0, 0x03, 0x5f, 0xd6,
		},
		{ // subr2
			0xfd, 0x7b, 0xbf, 0xa9,
			0xfd, 0x03, 0x00, 0x91,
			0x00, 0x00, 0x00, 0x94,
			0x08, 0x78, 0x48, 0x11,
			0x00, 0x39, 0x22, 0x11,
			0xfd, 0x7b, 0xc1, 0xa8,
			0xc0, 0x03, 0x5f, 0xd6,
		},
	}
	for i, code := range codes {

		insts, err := ArchARM64.DecodeBlock(code)
		if err != nil {
			t.Fatal(i, err)
		}
		nice := ArchARM64.GoSyntaxBlock(insts, 0x0, func(addr uint64) (name string, base uint64) {
			fmt.Printf("%x: attempt to lookup: %v\n", i, addr)
			return "", 0
		}, bytes.NewReader(code))

		fmt.Printf("---------\n%s\n----------------\n", strings.Join(nice, "\n"))
	}
}

func TestDisasmAMD64(t *testing.T) {
	codes := [][]byte{
		{ // subr
			0x55, 0x48, 0x89, 0xe5, 0xb8, 0x47, 0xf4, 0x10, 0x0, 0x5d, 0xc3,
		},
		{ // subr2
			0x55, 0x48, 0x89, 0xe5, 0xe8, 0x0, 0x0, 0x0, 0x0, 0x5, 0x8e, 0xe8, 0x21, 0x0, 0x5d, 0xc3,
		},
		{
			// vpaddq %xmm1, %xmm2, %xmm3
			0xc5, 0xe9, 0xd4, 0xd9,
		},
		// {
		// 	0x62, 0xf2, 0xfe, 0x48, 0x2a, 0xc9,
		// },
	}

	for i, code := range codes {

		insts, err := ArchAMD64.DecodeBlock(code)
		if err != nil {
			t.Fatal(i, err)
		}

		fmt.Printf("%+#v\n", insts[0])

		nice := ArchAMD64.GoSyntaxBlock(insts, 0x0, func(addr uint64) (name string, base uint64) {
			fmt.Printf("%x: attempt to lookup: %v\n", i, addr)
			return "SSSSS", addr
		}, bytes.NewReader(code))

		fmt.Printf("---------\n%s\n----------------\n", strings.Join(nice, "\n"))
	}
}
