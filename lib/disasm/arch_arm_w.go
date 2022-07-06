package disasm

import (
	"io"

	"golang.org/x/arch/arm/armasm"
)

var ArchARM = archARM{mode: armasm.ModeARM}

type archARM struct {
	mode armasm.Mode
}

func (arm archARM) GoSyntax(inst armasm.Inst, pc uint64, symname SymLookup, text io.ReaderAt) string {
	return GoSyntax(inst, pc, symname, text)
}

func (arm archARM) GoSyntaxBlock(insts []armasm.Inst, pc uint64, symname SymLookup, text io.ReaderAt) []string {
	var fs []string
	for _, inst := range insts {
		f := arm.GoSyntax(inst, pc, symname, text)
		pc = pc + uint64(inst.Len)
		fs = append(fs, f)
	}
	return fs
}

func (arm archARM) Decode(code []byte) (inst armasm.Inst, err error) {
	return armasm.Decode(code, arm.mode)
}

func (arm archARM) DecodeBlock(code []byte) (insts []armasm.Inst, err error) {
	var i int
	for i < len(code) {
		var inst armasm.Inst
		inst, err = arm.Decode(code[i:])
		if err != nil {
			return
		}
		insts = append(insts, inst)
		i = i + inst.Len
	}
	return
}
