package disasm2

import (
	"encoding/binary"
	"strconv"
	"strings"
)

type Text struct {
	Asm      string
	Comments []string
}

func (t Text) Prev() Text {
	last := len(t.Comments)
	t.Asm = t.Comments[last-1]
	t.Comments = t.Comments[:last-1]
	return t
}

func (t Text) Next() Text {
	t.Comments = append(t.Comments, t.Asm)
	t.Asm = ""
	return t
}

func (t Text) String() string {
	if t.Comments == nil {
		return t.Asm
	}
	return t.Asm + "\t// " + strings.Join(t.Comments, "\t// ")
}

func instEncodeRawBytes(bo binary.ByteOrder, b []byte) (insts []string) {
	var nb int
	for len(b) > 0 {
		switch {
		case len(b) >= 8:
			v := bo.Uint64(b)
			insts = append(insts, "QUAD $0x"+strconv.FormatUint(v, 16))
			nb = 8
		case len(b) >= 4:
			v := bo.Uint32(b)
			insts = append(insts, "LONG $0x"+strconv.FormatUint(uint64(v), 16))
			nb = 4
		case len(b) >= 2:
			v := bo.Uint16(b)
			insts = append(insts, "WORD $0x"+strconv.FormatUint(uint64(v), 16))
			nb = 2
		default:
			insts = append(insts, "BYTE $0x"+strconv.FormatUint(uint64(b[0]), 16))
			nb = 1
		}
		b = b[nb:]
	}
	return
}
