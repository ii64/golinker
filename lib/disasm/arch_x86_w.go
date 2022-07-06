package disasm

import (
	"fmt"
	"io"

	gs "github.com/knightsc/gapstone"
	"golang.org/x/arch/x86/x86asm"
)

var Arch386 = archX86{mode: 32}.init()
var ArchAMD64 = archX86{mode: 64}.init()

type archX86 struct {
	mode int
	e    gs.Engine
}

func (x86 archX86) init() archX86 {
	var csMode int
	switch x86.mode {
	case 32:
		csMode = gs.CS_MODE_32
	case 64:
		csMode = gs.CS_MODE_64
	}
	x86.e, _ = gs.New(gs.CS_ARCH_X86, csMode)
	return x86
}

func (x86 archX86) GoSyntax(inst x86asm.Inst, pc uint64, symname SymLookup, _ io.ReaderAt) string {
	return GoSyntax(inst, pc, symname, nil)
}

func (x86 archX86) GoSyntaxBlock(insts []x86asm.Inst, pc uint64, symname SymLookup, _ io.ReaderAt) []string {
	var fs []string
	for _, inst := range insts {
		f := x86.GoSyntax(inst, pc, symname, nil)
		f = fmt.Sprintf("%x: %s", pc, f)
		pc = pc + uint64(inst.Len)
		fs = append(fs, f)
	}
	return fs
}

func (x86 archX86) Decode(code []byte) (inst x86asm.Inst, err error) {
	return x86asm.Decode(code, x86.mode)
}

func (x86 archX86) DecodeFallback(code []byte) (inst gs.Instruction, err error) {
	var ret []gs.Instruction
	ret, err = x86.e.Disasm(code, 0x0, 1)
	if err != nil {
		return
	}
	inst = ret[0]
	return
}

func (x86 archX86) DecodeBlock(code []byte) (insts []x86asm.Inst, err error) {
	var i int
	for i < len(code) {
		var inst x86asm.Inst
		inst, err = x86.Decode(code[i:])
		if err != nil {
			return
		}
		insts = append(insts, inst)
		i = i + inst.Len
	}
	return
}

// ----
