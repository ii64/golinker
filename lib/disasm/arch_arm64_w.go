package disasm

import (
	"io"

	"golang.org/x/arch/arm64/arm64asm"
)

var ArchARM64 = archARM64{size: 4} // constant.

type archARM64 struct {
	size uint64
}

func (arm64 archARM64) GoSyntax(inst arm64asm.Inst, pc uint64, symname SymLookup, text io.ReaderAt) string {
	return arm64asm.GoSyntax(inst, pc, symname, text)
}

func (arm64 archARM64) GoSyntaxBlock(insts []arm64asm.Inst, pc uint64, symname SymLookup, text io.ReaderAt) []string {
	var fs []string
	for _, inst := range insts {
		f := arm64.GoSyntax(inst, pc, symname, text)
		pc = pc + arm64.size
		fs = append(fs, f)
	}
	return fs
}

func (arm64 archARM64) Decode(code []byte) (inst arm64asm.Inst, err error) {
	return arm64asm.Decode(code)
}

func (arm64 archARM64) DecodeBlock(code []byte) (insts []arm64asm.Inst, err error) {
	var i int
	for i < len(code) {
		var inst arm64asm.Inst
		inst, err = arm64.Decode(code[i:])
		if err != nil {
			return
		}
		insts = append(insts, inst)
		i = i + int(arm64.size)
	}
	return
}
