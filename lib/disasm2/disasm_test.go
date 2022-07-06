package disasm2

import (
	"fmt"
	"log"
	"testing"

	"github.com/ii64/golinker/lib/disasm"
	"github.com/knightsc/gapstone"
	"golang.org/x/arch/x86/x86asm"

	"github.com/twitchyliquid64/golang-asm/asm/arch"
)

func TestInit(t *testing.T) {
	code := []byte{
		// VPADDQ X1, X2, X3
		// vpaddq %xmm1, %xmm2, %xmm3
		0xc5, 0xe9, 0xd4, 0xd9,
		// MOVQ $1, AX
		// mov $1, %rax
		0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
		// VPADDQ Y1, Y2, Y3
		// vpaddq %ymm1, %ymm2,%ymm3
		0xc5, 0xed, 0x58, 0xd9,
		// MOVQ $1, AX
		// mov $1, %rax
		0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
		// MOVQ $2222, ret+8(FP)
		// mov $0x8ae, 8(%rsp)
		0x48, 0xc7, 0x44, 0x24, 0x10, 0xae, 0x08, 0x00, 0x00,
		// RET
		0xc3,

		// lea    (%rbx,%rax,1),%rdx
		0x48, 0x8d, 0x14, 0x03,
		// lea    (%rdx,%rbx,1),%rax
		0x48, 0x8d, 0x04, 0x1a,

		// mov    %fs:0xfffffffffffffff8,%r14
		0x64, 0x4c, 0x8b, 0x34, 0x25, 0xf8, 0xff, 0xff, 0xff,
		// mov    %fs:0x0,%r14
		0x64, 0x4c, 0x8b, 0x34, 0x25, 0x00, 0x00, 0x00, 0x00,

		// cmp    0x10(%r14),%r12
		0x4d, 0x3b, 0x66, 0x10,
		// jbe    f <p>
		0x76, 0x00,
		// mov    $0x1,%rax
		0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
		// call   1b <kk>
		0xe8, 0x00, 0x00, 0x00, 0x00,

		// 000000000000001b <kk>:
		// mov    $0xc,%rax
		0x48, 0xc7, 0xc0, 0x0c, 0x00, 0x00, 0x00,
		0xc3,
	}

	pc := 0
	for pc < len(code) {
		inst, err := disasm.ArchAMD64.Decode(code[pc:])
		if err != nil {
			log.Println(err)
			pc++
			continue
		}
		pc = pc + inst.Len
		log.Printf("%s\t\t%+#v\n", inst.String(), inst)
	}

	fmt.Printf("\n\n")

	pc = 0
	for pc < len(code) {
		inst, err := ArchAMD64.Decode(code[pc:])
		if err != nil {
			log.Println(err)
			pc++
			continue
		}
		st := ArchAMD64.GoSyntax(inst, uint64(pc), nil, nil)
		log.Printf("%+#v\n%+#v\n%#x:\t%s\n\t%s\n\n", inst.X86, inst,
			pc,
			inst.Mnemonic+" "+inst.OpStr,
			st,
		)
		pc = pc + int(inst.Size)
	}

}

func TestCompat(t *testing.T) {
	inst := &gapstone.X86Instruction{Prefix: []uint8{0x0, 0x0, 0x0, 0x0}, Opcode: []uint8{0xc7, 0x0, 0x0, 0x0}, Rex: 0x48, AddrSize: 0x8, ModRM: 0xc0, Sib: 0x0, Disp: 0, SibIndex: 0x0, SibScale: 0, SibBase: 0x0, XopCC: 0x0, SseCC: 0x0, AvxCC: 0x0, AvxSAE: false, AvxRM: 0x0, EFlags: 0x0, FPUFlags: 0x0, Operands: []gapstone.X86Operand{gapstone.X86Operand{Type: 0x2, Reg: 0x0, Imm: 1, Mem: gapstone.X86MemoryOperand{Segment: 0x0, Base: 0x0, Index: 0x0, Scale: 0, Disp: 0}, Size: 0x8, Access: 0x0, AvxBcast: 0x0, AvxZeroOpmask: false}, gapstone.X86Operand{Type: 0x1, Reg: 0x23, Imm: 0, Mem: gapstone.X86MemoryOperand{Segment: 0x0, Base: 0x0, Index: 0x0, Scale: 0, Disp: 0}, Size: 0x8, Access: 0x2, AvxBcast: 0x0, AvxZeroOpmask: false}}, Encoding: gapstone.X86Encoding{ModRMOffset: 0x2, DispOffset: 0x0, DispSize: 0x0, ImmOffset: 0x3, ImmSize: 0x4}}
	hdr := gapstone.Instruction{
		InstructionHeader: gapstone.InstructionHeader{
			Id: 0x1c1, Address: 0x4, Size: 0x7,
			Bytes:    []uint8{0x48, 0xc7, 0xc0, 0x1, 0x0, 0x0, 0x0},
			Mnemonic: "movq", OpStr: "$1, %rax",
			AllRegistersRead: []uint(nil), AllRegistersWritten: []uint{0x23},
			RegistersRead:    []uint(nil),
			RegistersWritten: []uint(nil), Groups: []uint(nil)},
		X86: inst,
	}
	// inst.
	_ = hdr
	ins := x86asm.Inst{
		Prefix: x86asm.Prefixes{0x8048, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		Op:     x86asm.MOV,
		Args: x86asm.Args{
			x86asm.Reg(x86asm.EAX), // dst
			x86asm.Imm(1),          // src, imm
		},
		// x86asm.Arg(0x35), 1, x86asm.Arg(nil), x86asm.Arg(nil)},
		Mode: 64, AddrSize: 64, DataSize: 64,
		MemBytes: 0, PCRel: 0,
		PCRelOff: 0,
	}
	_ = ins

	fmt.Printf("%d\n", arch.Set("amd64").Instructions["VADDPD"])
	fmt.Printf("%d\n", arch.Set("amd64").Instructions["RETW"])

	fins := x86asm.GoSyntax(ins, 0x0, nil)
	fmt.Println(fins)
}
