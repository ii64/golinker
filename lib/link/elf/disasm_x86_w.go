package elf

import (
	"fmt"
	"strings"

	"github.com/ii64/golinker/lib/disasm2"
	gs "github.com/knightsc/gapstone"
)

func (st *LinkState) doDisasm386() (err error) {
	return
}

func (st *LinkState) doDisasmAMD64() (err error) {
	var insts []gs.Instruction

	for _, fnAddr := range st.sFnOrder {
		code, exist := st.sFn[fnAddr]
		fnName, exist2 := st.sFnName[fnAddr]
		if !exist || !exist2 {
			return fmt.Errorf("FUNC data or name is not resolved")
		}

		// if strings.Contains(fnName, fmt.Sprintf("%s_aligner", st.cfg.NativeEntryName)) {
		// 	continue
		// }

		insts, err = disasm2.ArchAMD64.DecodeBlock(code, fnAddr)
		if err != nil {
			err = fmt.Errorf("disasm %s (%x) :%w",
				fnName, fnAddr,
				err)
			return
		}

		err = st.inspectInstsAMD64(fnAddr, insts)
		if err != nil {
			return
		}

		fs := disasm2.ArchAMD64.GoSyntaxBlock(insts, fnAddr, st.resolveSymbol2, nil)

		fmt.Printf("---- %s (%x) stk:%d ----\n", fnName, fnAddr, st.sFnStackSz[fnAddr])
		for i, _ := range insts {
			inst := &insts[i]
			asmfmt := fs[i]
			addr := uint64(inst.Address)

			// !! check for entry-relative call/jmp
			// by checking the string operand
			if strings.Contains(asmfmt.Asm, st.cfg.NativeEntryName) {
				tmp := asmfmt.Next()
				var asmstrs []string
				for _, ts := range disasm2.ArchAMD64.EncodeRawBytes(inst.Bytes) {
					asmstrs = append(asmstrs, ts.Asm)
				}
				tmp.Asm = strings.Join(asmstrs, "; ")
				st.sIns[addr] = tmp
			} else {
				st.sIns[addr] = asmfmt
			}

			st.sInsList = append(st.sInsList, addr)

			fmt.Printf("%x:\t%s\n", inst.Address, asmfmt)
		}
	}
	return
}

func (st *LinkState) inspectInstsAMD64(fnOff uint64, insts []gs.Instruction) (err error) {
	// check PC relative access, if it is not within .text
	// section, mark the instruction for DATA access
	// although there is some possibility that PC/Mem relative
	// access can be masked with some more instructions (obfuscation)
	// and/or junks, we can't check that here.
	// In x86, [noun] can laying down data within the .text section
	// See https://9p.io/sys/doc/asm.html about "Laying down data"

	// compute stack size
	st.sFnStackSz[fnOff] = disasm2.ArchAMD64.StackSize(insts)

	// register empty instruction addr
	for _, inst := range insts {
		st.sIns[uint64(inst.Address)] = disasm2.Text{}
	}

	// create label
	st.sLabelSym[fnOff] = fmt.Sprintf("__subr_%s__off_%d", st.sFnName[fnOff], fnOff)

	return
}
