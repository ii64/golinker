package disasm

import (
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/arch/arm/armasm"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/ppc64/ppc64asm"
	"golang.org/x/arch/x86/x86asm"
)

// https://cs.opensource.google/go/go/+/master:src/cmd/internal/objfile/disasm.go;l=386;drc=530511bacccdea0bb8a0fec644887c2613535c50;bpv=1;bpt=1

// var disasms = map[string]DisasmFuncStr{
// 	"386":     disasm_386_str,
// 	"amd64":   disasm_amd64_str,
// 	"arm":     disasm_arm_str,
// 	"arm64":   disasm_arm64_str,
// 	"ppc64":   disasm_ppc64_str_gen(byteOrders["ppc64"]),
// 	"ppc64le": disasm_ppc64_str_gen(byteOrders["ppc64le"]),
// }

var byteOrders = map[string]binary.ByteOrder{
	"386":     binary.LittleEndian,
	"amd64":   binary.LittleEndian,
	"arm":     binary.LittleEndian,
	"arm64":   binary.LittleEndian,
	"ppc64":   binary.BigEndian,
	"ppc64le": binary.LittleEndian,
	"s390x":   binary.BigEndian,
}

type DisasmFuncStr func(code []byte, pc uint64, symname SymLookup, text io.ReaderAt) (f string, size int, err error)

type SymLookup func(addr uint64) (name string, base uint64)

func GoSyntax(inst any, pc uint64, symname SymLookup, text io.ReaderAt) string {
	switch inst := inst.(type) {
	case x86asm.Inst:
		return x86asm.GoSyntax(inst, pc, x86asm.SymLookup(symname))
	case armasm.Inst:
		return armasm.GoSyntax(inst, pc, symname, text)
	case arm64asm.Inst:
		return arm64asm.GoSyntax(inst, pc, symname, text)
	case ppc64asm.Inst:
		return ppc64asm.GoSyntax(inst, pc, symname)
	}
	panic(fmt.Sprintf("go syntax format not supported: %T", inst))
}
