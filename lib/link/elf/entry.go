package elf

import (
	"fmt"

	"github.com/ii64/golinker/lib/disasm2"
	"github.com/knightsc/gapstone"
)

func (st *LinkState) loadEntrypoint() (err error) {
	switch st.Arch {
	case "amd64":
		code, _ := entryAMD64()
		st.registerEntrypoint("native_entry", code)

		// sz := uint64(len(code))
		// st.sProgData = append(st.sProgData, code...)
		// // !! set base addr after entrypoint
		// st.sBaseAddr = sz

		// // register entry fn
		// st.sFnSize[0x0] = sz
		// st.sFnOrder = append(st.sFnOrder, 0)

		st.sBaseAddr = st.sFnLastOff
		return
	case "arm64":
		code, _ := entryARM64()
		st.registerEntrypoint("native_entry", code)
		st.sBaseAddr = st.sFnLastOff
		return
	}
	return fmt.Errorf("sym entrypoint not implemented")
}

func entryAMD64() (code []byte, fs []disasm2.Text) {
	code = []byte{
		// lea    -0x7(%rip),%rax
		0x48, 0x8d, 0x05, 0xf9, 0xff, 0xff, 0xff,

		// mov    %rax,0x8(%rsp)
		// 0x48, 0x89, 0x44, 0x24, 0x08,

		// MOVQ AX, ret+8(FP)
		// mov    %rax,0x10(%rsp)
		0x48, 0x89, 0x44, 0x24, 0x10,

		// ret
		0xc3,
	}

	var err error
	var insts []gapstone.Instruction
	insts, err = disasm2.ArchAMD64.DecodeBlock(code, 0x0)
	if err != nil {
		panic("entry disasm failed")
	}
	fs = disasm2.ArchAMD64.GoSyntaxBlock(insts, 0x0, nil, nil)

	return
}

func entryARM64() (code []byte, fs []disasm2.Text) {
	panic("wip")
}
