package disasm

import (
	"encoding/binary"
	"io"

	"golang.org/x/arch/arm/armasm"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/ppc64/ppc64asm"
	"golang.org/x/arch/x86/x86asm"
)

// https://cs.opensource.google/go/go/+/master:src/cmd/internal/objfile/disasm.go;l=386;drc=530511bacccdea0bb8a0fec644887c2613535c50;bpv=1;bpt=1

func disasm_386(code []byte) (inst x86asm.Inst, err error) {
	return x86asm.Decode(code, 32)
}

func disasm_386_str(code []byte, pc uint64, symname SymLookup, _ io.ReaderAt) (f string, size int, err error) {
	var inst x86asm.Inst

	inst, err = disasm_386(code)
	if err != nil {
		return
	}
	f = x86asm.GoSyntax(inst, pc, x86asm.SymLookup(symname))
	size = inst.Len
	return
}

func disasm_amd64(code []byte) (inst x86asm.Inst, err error) {
	return x86asm.Decode(code, 64)
}

func disasm_amd64_str(code []byte, pc uint64, symname SymLookup, _ io.ReaderAt) (f string, size int, err error) {
	var inst x86asm.Inst
	inst, err = disasm_amd64(code)
	if err != nil {
		return
	}
	f = x86asm.GoSyntax(inst, pc, x86asm.SymLookup(symname))
	size = inst.Len
	return
}

func disasm_arm(code []byte) (inst armasm.Inst, err error) {
	return armasm.Decode(code, armasm.ModeARM)
}

func disasm_arm_str(code []byte, pc uint64, symname SymLookup, text io.ReaderAt) (f string, size int, err error) {
	var inst armasm.Inst
	inst, err = disasm_arm(code)
	if err != nil {
		return
	}
	f = armasm.GoSyntax(inst, pc, symname, text)
	size = inst.Len
	return
}

func disasm_arm64(code []byte) (inst arm64asm.Inst, err error) {
	return arm64asm.Decode(code)
}

func disasm_arm64_str(code []byte, pc uint64, symname SymLookup, text io.ReaderAt) (f string, size int, err error) {
	var inst arm64asm.Inst
	inst, err = disasm_arm64(code)
	if err != nil {
		return
	}
	f = arm64asm.GoSyntax(inst, pc, symname, text)
	size = 4
	return
}

func disasm_ppc64(code []byte, byteOrder binary.ByteOrder) (inst ppc64asm.Inst, err error) {
	return ppc64asm.Decode(code, byteOrder)
}

func disasm_ppc64_str(code []byte, pc uint64, symname SymLookup, byteOrder binary.ByteOrder) (f string, size int, err error) {
	var inst ppc64asm.Inst
	inst, err = disasm_ppc64(code, byteOrder)
	if err != nil {
		return
	}
	f = ppc64asm.GoSyntax(inst, pc, symname)
	size = inst.Len
	return
}

func disasm_ppc64_gen(byteOrder binary.ByteOrder) func([]byte) (ppc64asm.Inst, error) {
	return func(code []byte) (inst ppc64asm.Inst, err error) {
		return disasm_ppc64(code, byteOrder)
	}
}

func disasm_ppc64_str_gen(byteOrder binary.ByteOrder) func([]byte, uint64, SymLookup, io.ReaderAt) (string, int, error) {
	return func(b []byte, pc uint64, symname SymLookup, _ io.ReaderAt) (f string, size int, err error) {
		f, size, err = disasm_ppc64_str(b, pc, symname, byteOrder)
		return
	}
}
