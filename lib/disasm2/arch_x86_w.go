package disasm2

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	gs "github.com/knightsc/gapstone"
	"github.com/twitchyliquid64/golang-asm/asm/arch"
)

// ref
// https://quasilyte.dev/blog/post/go-asm-complementary-reference/

var ArchAMD64 = archX86{mode: 64}.init()
var Arch386 = archX86{mode: 32}.init()

var X86JustWriteRawBytes = false
var X86RawBytesFallback = false

var (
	x86JmpJcc        = map[string]bool{}
	x86InstUseSymbol = map[string]bool{
		"JMP": true,
		"JE":  true,
		"JG":  true,
		"JLE": true,
		"JNE": true,
		"JLS": true,
		"JGE": true,
		"JLT": true,
		"JCC": true,
		"JBE": true,
		"JL":  true,
		"JAE": true,
		"JA":  true,
		"JMI": true,
		"JPL": true,
		"JS":  true,
		"JNS": true,
		"JB":  true,
		"JCS": true,

		"CALL": true,
	}
	x86DisallowedInstruction = map[string]bool{
		"SYSCALL": true,

		"IMULQ": true,
		"IMULL": true,
		"PUSHQ": true,
		"POPQ":  true,

		// 83e0f0         andl    $0xfffffff0, %eax
		// 25f0ffffff     andl    $0xfffffff0, %eax
		"ANDL": true,

		"NOPW": true, "NOPL": true, "NOP": true,
	}
	x86DisallowedRegisterOperand = map[string]bool{
		"RIP": true, "EIP": true, "IP": true,
	}

	x86MnemonicReplace = map[string]string{
		// "MOVZBL": "MOVBLZX",
		// "MOVABSL": "",

		"RETQ":  "RET",
		"CALLQ": "CALL",
	}
)

type archX86 struct {
	mode int
	_AC  *arch.Arch
	e    gs.Engine
}

func (m archX86) init() archX86 {
	m = archX86{mode: m.mode}
	var csMode int
	switch m.mode {
	case 32:
		m._AC = arch.Set("386")
		csMode = gs.CS_MODE_32
	case 64:
		m._AC = arch.Set("amd64")
		csMode = gs.CS_MODE_64
	default:
		panic("unknown x86 mode")
	}
	var err error
	m.e, err = gs.New(gs.CS_ARCH_X86, csMode)
	if err != nil {
		panic(err)
	}
	err = m.e.SetOption(gs.CS_OPT_SYNTAX, gs.CS_OPT_SYNTAX_ATT)
	if err != nil {
		panic(err)
	}
	err = m.e.SetOption(gs.CS_OPT_DETAIL, gs.CS_OPT_ON)
	if err != nil {
		panic(err)
	}
	return m
}

func (m archX86) Nop(sz int) []byte {
	b := make([]byte, 0, 8)
	i := sz
	for i > 0 {
		switch {
		case i >= 9:
			b = append(b, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00)
			i -= 9
		case i >= 8:
			b = append(b, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00)
			i -= 8
		case i >= 7:
			b = append(b, 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00)
			i -= 7
		case i >= 6:
			b = append(b, 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00)
			i -= 6
		case i >= 5:
			b = append(b, 0x0F, 0x1F, 0x44, 0x00, 0x00)
			i -= 5
		case i >= 4:
			b = append(b, 0x0F, 0x1F, 0x40, 0x00)
			i -= 4
		case i >= 3:
			b = append(b, 0x0F, 0x1F, 0x00)
			i -= 3
		case i >= 2:
			b = append(b, 0x66, 0x90)
			i -= 2
		default:
			b = append(b, 0x90)
			i--
		}
	}
	return b
}

func (m archX86) StackSize(insts []gs.Instruction) uint64 {
	switch m.mode {
	case 64:
		alloc, access := m.stackSizeAMD64(insts)
		if alloc > access {
			return alloc
		}
		return access
	}
	panic("not implemented")
}

func (m archX86) stackSizeAMD64(insts []gs.Instruction) (alloc, access uint64) {
	var allocMax uint64
	var accessMax uint64
	for _, inst := range insts {
		for _, opr := range inst.X86.Operands {

			// count operation on SP/BP
			if opr.Type == gs.X86_OP_REG {
				reg := m.fmtRegToGroup(inst, opr.Reg)
				mn := m.cvtMnemonic(inst.Mnemonic)
				if reg != "SP" {
					continue
				}
				// sub $imm, %rsp
				if strings.HasPrefix(mn, "SUB") {
					// find imm opr
					for _, opr := range inst.X86.Operands {
						if opr.Type == gs.X86_OP_IMM {
							if opr.Imm > int64(allocMax) { // must be positive
								allocMax = uint64(opr.Imm)
							}
						}
					}
				}
			}

			// count memory access to SP/BP register
			if opr.Type == gs.X86_OP_MEM {
				reg := m.fmtRegToGroup(inst, opr.Mem.Base)
				if reg != "SP" {
					continue
				}
				if off := opr.Mem.Disp; off > int64(accessMax) { // must be positive
					accessMax = uint64(off)
				}
			}

		}
	}
	return allocMax, accessMax
}

// ref: https://github.com/chenzhuoyu/asm2asm/blob/5e85f0dbbd2eb4768d8413c326e5540612c86fae/asm2asm.py#L411-L431
// convert capstone ATT mnemonic str
/*
__instr_map__ = {
        'INT3'       : INT3,

        'MOVQ'       : Special.MOVQ,
        'CBTW'       : x86_64.CBW,
        'CWTL'       : x86_64.CWDE,
        'CLTQ'       : x86_64.CDQE,

        'MOVZBW'     : x86_64.MOVZX,
        'MOVZBL'     : x86_64.MOVZX,
        'MOVZWL'     : x86_64.MOVZX,
        'MOVZBQ'     : x86_64.MOVZX,
        'MOVZWQ'     : x86_64.MOVZX,

        'MOVSBW'     : x86_64.MOVSX,
        'MOVSBL'     : x86_64.MOVSX,
        'MOVSWL'     : x86_64.MOVSX,
        'MOVSBQ'     : x86_64.MOVSX,
        'MOVSWQ'     : x86_64.MOVSX,

        'MOVSLQ'     : x86_64.MOVSXD,
        'MOVABSQ'    : x86_64.MOV,

        'VCMPEQPS'   : VCMPEQPS,
        'VCMPTRUEPS' : VCMPTRUEPS,
    }
*/

func (m archX86) cvtMnemonicInternal(mnemStr string) (string, bool) {
	mnCap := strings.ToUpper(mnemStr)

	mnRep, exist := x86MnemonicReplace[mnCap]
	if exist {
		mnCap = mnRep
	}
	// check if mnem on Go asm sets
	_, exist = m._AC.Instructions[mnCap]
	return mnCap, exist
}

func (m archX86) cvtMnemonic(mnemStr string) string {
	mnCap, exist := m.cvtMnemonicInternal(mnemStr)
	if !exist && !X86RawBytesFallback {
		panic(fmt.Sprintf("mnemonic not defined: %s (%s)", mnCap, mnemStr))
	}
	return mnCap
}

// convert capstone ATT operand str
func (m archX86) cvtOprStr(inst gs.Instruction, symname SymLookup) string {
	var ops []string

	switch mn := m.cvtMnemonic(inst.Mnemonic); mn {
	default:
		switch {
		case strings.HasPrefix(mn, "CMP"):
			inst.X86.Operands[0], inst.X86.Operands[1] = inst.X86.Operands[1], inst.X86.Operands[0]
		}
	}

	for _, op := range inst.X86.Operands {
		ops = append(ops, m.fmtOperandGoSyntax(inst, op, symname))
	}
	return strings.Join(ops, ", ")
}

func (m archX86) fmtNum(num int64, hex bool) string {
	if !hex {
		return strconv.FormatInt(num, 10)
	}
	numS := strconv.FormatInt(num, 16)
	if numS[0] == '-' {
		return "-0x" + numS[1:]
	}
	return "0x" + numS
}

func (m archX86) hasDisallowedInstruction(inst gs.Instruction) bool {
	mn := m.cvtMnemonic(inst.Mnemonic)
	doDisallow, disallowed := x86DisallowedInstruction[mn]
	return disallowed && doDisallow
}

func (m archX86) hasDisallowedRegisterOperand(inst gs.Instruction) bool {
	for _, opr := range inst.X86.Operands {
		var regNms []string
		switch opr.Type {
		case gs.X86_OP_REG: // check Reg
			regNms = append(regNms, x86RegisterMap[opr.Reg])
		case gs.X86_OP_MEM: // check Mem
			switch {
			case opr.Mem.Segment != 0:
				regNms = append(regNms, x86RegisterMap[opr.Mem.Segment])
			case opr.Mem.Base != 0:
				regNms = append(regNms, x86RegisterMap[opr.Mem.Base])
			}
			if opr.Mem.Index != 0 {
				regNms = append(regNms, x86RegisterMap[opr.Mem.Index])
			}
		case gs.X86_OP_IMM: // continue Imm
			continue
		default: // fallback
			continue
		}
		for _, regNm := range regNms {
			doDisallow, disallowed := x86DisallowedRegisterOperand[regNm]
			if disallowed && doDisallow {
				return true
			}
		}
	}
	return false
}

func (m archX86) hasMemoryOperand(inst gs.Instruction) bool {
	for _, op := range inst.X86.Operands {
		if op.Type == gs.X86_OP_MEM {
			return true
		}
	}
	return false
}

func (m archX86) fmtReg(inst gs.Instruction, reg uint) string {
	mnem := m.cvtMnemonic(inst.Mnemonic)
	_ = mnem

	// switch {
	// case m.hasMemoryOperand(inst):
	// 	// if inst don't have any MEM operand
	// 	// use grouped reg: RAX -> AX, EAX -> AX
	// 	return m.fmtRegToGroup(inst, reg)
	// }
	// return getX86RegisterGoSyntax(reg)
	return m.fmtRegToGroup(inst, reg)
}

func (m archX86) fmtRegToGroup(insnt gs.Instruction, reg uint) string {
	regS := getX86RegisterGoSyntax(reg)

	// -- GPR

	switch reg {
	case gs.X86_REG_RAX, gs.X86_REG_EAX,
		gs.X86_REG_AX, gs.X86_REG_AH, gs.X86_REG_AL:
		return "AX"
	case gs.X86_REG_RBX, gs.X86_REG_EBX,
		gs.X86_REG_BX, gs.X86_REG_BH, gs.X86_REG_BL:
		return "BX"
	case gs.X86_REG_RCX, gs.X86_REG_ECX,
		gs.X86_REG_CX, gs.X86_REG_CH, gs.X86_REG_CL:
		return "CX"
	case gs.X86_REG_RDX, gs.X86_REG_EDX,
		gs.X86_REG_DX, gs.X86_REG_DH, gs.X86_REG_DL:
		return "DX"

	case gs.X86_REG_RSP, gs.X86_REG_ESP, gs.X86_REG_SP, gs.X86_REG_SPL:
		return "SP"
	case gs.X86_REG_RBP, gs.X86_REG_EBP, gs.X86_REG_BP, gs.X86_REG_BPL:
		return "BP"
	case gs.X86_REG_RDI, gs.X86_REG_EDI, gs.X86_REG_DI, gs.X86_REG_DIL:
		return "DI"
	case gs.X86_REG_RSI, gs.X86_REG_ESI, gs.X86_REG_SI, gs.X86_REG_SIL:
		return "SI"

	case gs.X86_REG_R8, gs.X86_REG_R8D, gs.X86_REG_R8W, gs.X86_REG_R8B:
		return "R8"
	case gs.X86_REG_R9, gs.X86_REG_R9D, gs.X86_REG_R9W, gs.X86_REG_R9B:
		return "R9"
	case gs.X86_REG_R10, gs.X86_REG_R10D, gs.X86_REG_R10W, gs.X86_REG_R10B:
		return "R10"
	case gs.X86_REG_R11, gs.X86_REG_R11D, gs.X86_REG_R11W, gs.X86_REG_R11B:
		return "R11"
	case gs.X86_REG_R12, gs.X86_REG_R12D, gs.X86_REG_R12W, gs.X86_REG_R12B:
		return "R12"
	case gs.X86_REG_R13, gs.X86_REG_R13D, gs.X86_REG_R13W, gs.X86_REG_R13B:
		return "R13"
	case gs.X86_REG_R14, gs.X86_REG_R14D, gs.X86_REG_R14W, gs.X86_REG_R14B:
		return "R14"
	case gs.X86_REG_R15, gs.X86_REG_R15D, gs.X86_REG_R15W, gs.X86_REG_R15B:
		return "R15"
	}

	return regS
}

// Note that `symname` need to mention (SB) or label name explicitly
func (m archX86) fmtOperandGoSyntax(inst gs.Instruction, op gs.X86Operand, symname SymLookup) string {
	mnem := m.cvtMnemonic(inst.Mnemonic)
	_ = mnem
	switch op.Type {
	case gs.X86_OP_REG:
		return m.fmtReg(inst, op.Reg)
	case gs.X86_OP_IMM:
		name, base := symname(uint64(op.Imm))
		prefix := "$"

		// tbd. limit symbol lookup just for far call/Jcc only?
		if _, exist := x86InstUseSymbol[mnem]; !exist {
			goto normal
		}

		if name != "" {
			prefix = "" // don't use Imm for known symbol
			suffix := ""
			if uint64(op.Imm) != base {
				suffix = fmt.Sprintf("%+d", inst.Address-uint(base))
			}
			return fmt.Sprintf("%s%s%s", prefix, name, suffix)
		}
		if m.mode == 32 {
			return fmt.Sprintf("%s%#x", prefix, uint32(inst.Address))
		}
	normal:
		return fmt.Sprintf("$%#x", op.Imm)
	case gs.X86_OP_MEM:
		segReg := m.fmtReg(inst, op.Mem.Segment)
		baseReg := m.fmtReg(inst, op.Mem.Base)
		idxReg := m.fmtReg(inst, op.Mem.Index)
		scale := m.fmtNum(int64(op.Mem.Scale), false)
		disp := m.fmtNum(op.Mem.Disp, true)

		//
		var opf string
		switch {
		case op.Mem.Segment != 0:
			opf = "(" + segReg + ")"
		case op.Mem.Base != 0:
			opf = "(" + baseReg + ")"
		}
		if op.Mem.Index != 0 { // reg
			opf = opf + "(" + idxReg + "*" + scale + ")"
		}
		if op.Mem.Disp == 0 {
			return opf
		}
		return disp + opf
	}
	panic("operand type unk")
}

func (m archX86) fmtInstRawBytes(inst gs.Instruction) Text {
	var res Text

	var comment string
	comment = inst.Mnemonic
	if inst.OpStr != "" {
		comment = comment + " " + inst.OpStr
	}
	res.Comments = append(res.Comments, comment)

	res.Asm = strings.Join(
		instEncodeRawBytes(m._AC.ByteOrder, inst.Bytes), "; ")

	return res
}

func (m archX86) EncodeRawBytes(b []byte) (ret []Text) {
	fs := instEncodeRawBytes(m._AC.ByteOrder, b)
	for _, f := range fs {
		ret = append(ret, Text{
			Asm: f,
		})
	}
	return
}

func (m archX86) fmtInst(inst gs.Instruction, symname SymLookup) Text {
	var asm string
	var opStr string
	isDisallowed := m.hasDisallowedInstruction(inst) || m.hasDisallowedRegisterOperand(inst) || X86JustWriteRawBytes

	// format as raw bytes
	rawInstruction := m.fmtInstRawBytes(inst)

	mn, mnExist := m.cvtMnemonicInternal(inst.Mnemonic)
	if !mnExist && X86RawBytesFallback {
		isDisallowed = true
		goto direct
	}

	opStr = m.cvtOprStr(inst, symname)
	if opStr == "" && !isDisallowed {
		asm = mn
		return Text{Asm: asm}
	}
	asm = mn + " " + opStr

direct:
	if isDisallowed {
		rawInstruction.Comments = append(rawInstruction.Comments, asm)
		return rawInstruction
	}
	return Text{Asm: asm}
}

// ----

// GoSyntax of disasm2
func (m archX86) GoSyntax(inst gs.Instruction, pc uint64, symname SymLookup, text io.ReaderAt) Text {
	if symname == nil {
		symname = func(addr uint64) (name string, base uint64) {
			return "", 0
		}
	}
	// override capstone addressing
	inst.Address = uint(pc)
	return m.fmtInst(inst, symname)
}

func (m archX86) GoSyntaxBlock(insts []gs.Instruction, pc uint64, symname SymLookup, text io.ReaderAt) []Text {
	var fs []Text
	for _, inst := range insts {
		f := m.GoSyntax(inst, pc, symname, text)
		pc = pc + uint64(inst.Size)
		fs = append(fs, f)
	}
	return fs

}

// -----

func (m archX86) Decode(code []byte) (inst gs.Instruction, err error) {
	var ret []gs.Instruction
	ret, err = m.e.Disasm(code, 0x0, 1)
	if err != nil {
		return
	}
	inst = ret[0]
	return
}

func (m archX86) DecodeBlock(code []byte, pc uint64) (insts []gs.Instruction, err error) {
	insts, err = m.e.Disasm(code, pc, 0)
	return
}

// capstone
// reg:     https://github.com/capstone-engine/capstone/blob/ea6b1a264689311ab11efb60354461e7990a2581/arch/X86/X86GenRegisterInfo.inc
// printer: https://github.com/capstone-engine/capstone/blob/ea6b1a264689311ab11efb60354461e7990a2581/arch/X86/X86ATTInstPrinter.c

// https://quasilyte.dev/blog/post/go-asm-complementary-reference/

// x86 register mapping
func getX86RegisterGoSyntax(reg uint) string {
	regNm, exist := x86RegisterMap[reg]
	if !exist {
		panic("x86 reg unk")
	}
	// the reg id is ordered
	switch {
	case reg >= gs.X86_REG_XMM0 && reg <= gs.X86_REG_XMM31:
		return "X" + regNm[3:]
	case reg >= gs.X86_REG_YMM0 && reg <= gs.X86_REG_YMM31:
		return "Y" + regNm[3:]
	case reg >= gs.X86_REG_ZMM0 && reg <= gs.X86_REG_ZMM31:
		return "Z" + regNm[3:]
	}
	return regNm
}

var x86RegisterMap = map[uint]string{
	gs.X86_REG_INVALID: "INVALID",
	gs.X86_REG_AH:      "AH",
	gs.X86_REG_AL:      "AL",
	gs.X86_REG_AX:      "AX",
	gs.X86_REG_BH:      "BH",
	gs.X86_REG_BL:      "BL",
	gs.X86_REG_BP:      "BP",
	gs.X86_REG_BPL:     "BPL",
	gs.X86_REG_BX:      "BX",
	gs.X86_REG_CH:      "CH",
	gs.X86_REG_CL:      "CL",
	gs.X86_REG_CS:      "CS",
	gs.X86_REG_CX:      "CX",
	gs.X86_REG_DH:      "DH",
	gs.X86_REG_DI:      "DI",
	gs.X86_REG_DIL:     "DIL",
	gs.X86_REG_DL:      "DL",
	gs.X86_REG_DS:      "DS",
	gs.X86_REG_DX:      "DX",
	gs.X86_REG_EAX:     "EAX",
	gs.X86_REG_EBP:     "EBP",
	gs.X86_REG_EBX:     "EBX",
	gs.X86_REG_ECX:     "ECX",
	gs.X86_REG_EDI:     "EDI",
	gs.X86_REG_EDX:     "EDX",
	gs.X86_REG_EFLAGS:  "EFLAGS",
	gs.X86_REG_EIP:     "EIP",
	gs.X86_REG_EIZ:     "EIZ",
	gs.X86_REG_ES:      "ES",
	gs.X86_REG_ESI:     "ESI",
	gs.X86_REG_ESP:     "ESP",
	gs.X86_REG_FPSW:    "FPSW",
	gs.X86_REG_FS:      "FS",
	gs.X86_REG_GS:      "GS",
	gs.X86_REG_IP:      "IP",
	gs.X86_REG_RAX:     "RAX",
	gs.X86_REG_RBP:     "RBP",
	gs.X86_REG_RBX:     "RBX",
	gs.X86_REG_RCX:     "RCX",
	gs.X86_REG_RDI:     "RDI",
	gs.X86_REG_RDX:     "RDX",
	gs.X86_REG_RIP:     "RIP",
	gs.X86_REG_RIZ:     "RIZ",
	gs.X86_REG_RSI:     "RSI",
	gs.X86_REG_RSP:     "RSP",
	gs.X86_REG_SI:      "SI",
	gs.X86_REG_SIL:     "SIL",
	gs.X86_REG_SP:      "SP",
	gs.X86_REG_SPL:     "SPL",
	gs.X86_REG_SS:      "SS",
	gs.X86_REG_CR0:     "CR0",
	gs.X86_REG_CR1:     "CR1",
	gs.X86_REG_CR2:     "CR2",
	gs.X86_REG_CR3:     "CR3",
	gs.X86_REG_CR4:     "CR4",
	gs.X86_REG_CR5:     "CR5",
	gs.X86_REG_CR6:     "CR6",
	gs.X86_REG_CR7:     "CR7",
	gs.X86_REG_CR8:     "CR8",
	gs.X86_REG_CR9:     "CR9",
	gs.X86_REG_CR10:    "CR10",
	gs.X86_REG_CR11:    "CR11",
	gs.X86_REG_CR12:    "CR12",
	gs.X86_REG_CR13:    "CR13",
	gs.X86_REG_CR14:    "CR14",
	gs.X86_REG_CR15:    "CR15",
	gs.X86_REG_DR0:     "DR0",
	gs.X86_REG_DR1:     "DR1",
	gs.X86_REG_DR2:     "DR2",
	gs.X86_REG_DR3:     "DR3",
	gs.X86_REG_DR4:     "DR4",
	gs.X86_REG_DR5:     "DR5",
	gs.X86_REG_DR6:     "DR6",
	gs.X86_REG_DR7:     "DR7",
	gs.X86_REG_DR8:     "DR8",
	gs.X86_REG_DR9:     "DR9",
	gs.X86_REG_DR10:    "DR10",
	gs.X86_REG_DR11:    "DR11",
	gs.X86_REG_DR12:    "DR12",
	gs.X86_REG_DR13:    "DR13",
	gs.X86_REG_DR14:    "DR14",
	gs.X86_REG_DR15:    "DR15",
	gs.X86_REG_FP0:     "FP0",
	gs.X86_REG_FP1:     "FP1",
	gs.X86_REG_FP2:     "FP2",
	gs.X86_REG_FP3:     "FP3",
	gs.X86_REG_FP4:     "FP4",
	gs.X86_REG_FP5:     "FP5",
	gs.X86_REG_FP6:     "FP6",
	gs.X86_REG_FP7:     "FP7",
	gs.X86_REG_K0:      "K0",
	gs.X86_REG_K1:      "K1",
	gs.X86_REG_K2:      "K2",
	gs.X86_REG_K3:      "K3",
	gs.X86_REG_K4:      "K4",
	gs.X86_REG_K5:      "K5",
	gs.X86_REG_K6:      "K6",
	gs.X86_REG_K7:      "K7",
	gs.X86_REG_MM0:     "MM0",
	gs.X86_REG_MM1:     "MM1",
	gs.X86_REG_MM2:     "MM2",
	gs.X86_REG_MM3:     "MM3",
	gs.X86_REG_MM4:     "MM4",
	gs.X86_REG_MM5:     "MM5",
	gs.X86_REG_MM6:     "MM6",
	gs.X86_REG_MM7:     "MM7",
	gs.X86_REG_R8:      "R8",
	gs.X86_REG_R9:      "R9",
	gs.X86_REG_R10:     "R10",
	gs.X86_REG_R11:     "R11",
	gs.X86_REG_R12:     "R12",
	gs.X86_REG_R13:     "R13",
	gs.X86_REG_R14:     "R14",
	gs.X86_REG_R15:     "R15",
	gs.X86_REG_ST0:     "ST0",
	gs.X86_REG_ST1:     "ST1",
	gs.X86_REG_ST2:     "ST2",
	gs.X86_REG_ST3:     "ST3",
	gs.X86_REG_ST4:     "ST4",
	gs.X86_REG_ST5:     "ST5",
	gs.X86_REG_ST6:     "ST6",
	gs.X86_REG_ST7:     "ST7",
	gs.X86_REG_XMM0:    "XMM0",
	gs.X86_REG_XMM1:    "XMM1",
	gs.X86_REG_XMM2:    "XMM2",
	gs.X86_REG_XMM3:    "XMM3",
	gs.X86_REG_XMM4:    "XMM4",
	gs.X86_REG_XMM5:    "XMM5",
	gs.X86_REG_XMM6:    "XMM6",
	gs.X86_REG_XMM7:    "XMM7",
	gs.X86_REG_XMM8:    "XMM8",
	gs.X86_REG_XMM9:    "XMM9",
	gs.X86_REG_XMM10:   "XMM10",
	gs.X86_REG_XMM11:   "XMM11",
	gs.X86_REG_XMM12:   "XMM12",
	gs.X86_REG_XMM13:   "XMM13",
	gs.X86_REG_XMM14:   "XMM14",
	gs.X86_REG_XMM15:   "XMM15",
	gs.X86_REG_XMM16:   "XMM16",
	gs.X86_REG_XMM17:   "XMM17",
	gs.X86_REG_XMM18:   "XMM18",
	gs.X86_REG_XMM19:   "XMM19",
	gs.X86_REG_XMM20:   "XMM20",
	gs.X86_REG_XMM21:   "XMM21",
	gs.X86_REG_XMM22:   "XMM22",
	gs.X86_REG_XMM23:   "XMM23",
	gs.X86_REG_XMM24:   "XMM24",
	gs.X86_REG_XMM25:   "XMM25",
	gs.X86_REG_XMM26:   "XMM26",
	gs.X86_REG_XMM27:   "XMM27",
	gs.X86_REG_XMM28:   "XMM28",
	gs.X86_REG_XMM29:   "XMM29",
	gs.X86_REG_XMM30:   "XMM30",
	gs.X86_REG_XMM31:   "XMM31",
	gs.X86_REG_YMM0:    "YMM0",
	gs.X86_REG_YMM1:    "YMM1",
	gs.X86_REG_YMM2:    "YMM2",
	gs.X86_REG_YMM3:    "YMM3",
	gs.X86_REG_YMM4:    "YMM4",
	gs.X86_REG_YMM5:    "YMM5",
	gs.X86_REG_YMM6:    "YMM6",
	gs.X86_REG_YMM7:    "YMM7",
	gs.X86_REG_YMM8:    "YMM8",
	gs.X86_REG_YMM9:    "YMM9",
	gs.X86_REG_YMM10:   "YMM10",
	gs.X86_REG_YMM11:   "YMM11",
	gs.X86_REG_YMM12:   "YMM12",
	gs.X86_REG_YMM13:   "YMM13",
	gs.X86_REG_YMM14:   "YMM14",
	gs.X86_REG_YMM15:   "YMM15",
	gs.X86_REG_YMM16:   "YMM16",
	gs.X86_REG_YMM17:   "YMM17",
	gs.X86_REG_YMM18:   "YMM18",
	gs.X86_REG_YMM19:   "YMM19",
	gs.X86_REG_YMM20:   "YMM20",
	gs.X86_REG_YMM21:   "YMM21",
	gs.X86_REG_YMM22:   "YMM22",
	gs.X86_REG_YMM23:   "YMM23",
	gs.X86_REG_YMM24:   "YMM24",
	gs.X86_REG_YMM25:   "YMM25",
	gs.X86_REG_YMM26:   "YMM26",
	gs.X86_REG_YMM27:   "YMM27",
	gs.X86_REG_YMM28:   "YMM28",
	gs.X86_REG_YMM29:   "YMM29",
	gs.X86_REG_YMM30:   "YMM30",
	gs.X86_REG_YMM31:   "YMM31",
	gs.X86_REG_ZMM0:    "ZMM0",
	gs.X86_REG_ZMM1:    "ZMM1",
	gs.X86_REG_ZMM2:    "ZMM2",
	gs.X86_REG_ZMM3:    "ZMM3",
	gs.X86_REG_ZMM4:    "ZMM4",
	gs.X86_REG_ZMM5:    "ZMM5",
	gs.X86_REG_ZMM6:    "ZMM6",
	gs.X86_REG_ZMM7:    "ZMM7",
	gs.X86_REG_ZMM8:    "ZMM8",
	gs.X86_REG_ZMM9:    "ZMM9",
	gs.X86_REG_ZMM10:   "ZMM10",
	gs.X86_REG_ZMM11:   "ZMM11",
	gs.X86_REG_ZMM12:   "ZMM12",
	gs.X86_REG_ZMM13:   "ZMM13",
	gs.X86_REG_ZMM14:   "ZMM14",
	gs.X86_REG_ZMM15:   "ZMM15",
	gs.X86_REG_ZMM16:   "ZMM16",
	gs.X86_REG_ZMM17:   "ZMM17",
	gs.X86_REG_ZMM18:   "ZMM18",
	gs.X86_REG_ZMM19:   "ZMM19",
	gs.X86_REG_ZMM20:   "ZMM20",
	gs.X86_REG_ZMM21:   "ZMM21",
	gs.X86_REG_ZMM22:   "ZMM22",
	gs.X86_REG_ZMM23:   "ZMM23",
	gs.X86_REG_ZMM24:   "ZMM24",
	gs.X86_REG_ZMM25:   "ZMM25",
	gs.X86_REG_ZMM26:   "ZMM26",
	gs.X86_REG_ZMM27:   "ZMM27",
	gs.X86_REG_ZMM28:   "ZMM28",
	gs.X86_REG_ZMM29:   "ZMM29",
	gs.X86_REG_ZMM30:   "ZMM30",
	gs.X86_REG_ZMM31:   "ZMM31",
	gs.X86_REG_R8B:     "R8B",
	gs.X86_REG_R9B:     "R9B",
	gs.X86_REG_R10B:    "R10B",
	gs.X86_REG_R11B:    "R11B",
	gs.X86_REG_R12B:    "R12B",
	gs.X86_REG_R13B:    "R13B",
	gs.X86_REG_R14B:    "R14B",
	gs.X86_REG_R15B:    "R15B",
	gs.X86_REG_R8D:     "R8D",
	gs.X86_REG_R9D:     "R9D",
	gs.X86_REG_R10D:    "R10D",
	gs.X86_REG_R11D:    "R11D",
	gs.X86_REG_R12D:    "R12D",
	gs.X86_REG_R13D:    "R13D",
	gs.X86_REG_R14D:    "R14D",
	gs.X86_REG_R15D:    "R15D",
	gs.X86_REG_R8W:     "R8W",
	gs.X86_REG_R9W:     "R9W",
	gs.X86_REG_R10W:    "R10W",
	gs.X86_REG_R11W:    "R11W",
	gs.X86_REG_R12W:    "R12W",
	gs.X86_REG_R13W:    "R13W",
	gs.X86_REG_R14W:    "R14W",
	gs.X86_REG_R15W:    "R15W",
	gs.X86_REG_ENDING:  "ENDING",
}
