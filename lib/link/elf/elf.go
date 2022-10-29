package elf

import (
	"debug/elf"
	"fmt"
	"go/ast"
	"io"
	"os"

	"github.com/ii64/golinker/conf"
	"github.com/ii64/golinker/lib/disasm2"
	"github.com/ii64/golinker/lib/hdr"
	"golang.org/x/exp/slices"
)

type LinkState struct {
	File *elf.File
	Arch string

	sBaseAddr uint64
	sSymbols  []elf.Symbol

	sProgData       []byte
	sProgSection    []elf.SectionIndex
	sProgSectionLoc map[elf.SectionIndex][2]uint64

	// hold starting PC, and prog data that's linked with sTextContent
	sFn        map[uint64][]byte
	sFnStackSz map[uint64]uint64
	sFnName    map[uint64]string
	sFnSize    map[uint64]uint64
	sFnOrder   []uint64
	sFnLastOff uint64

	// disasm inst with its PC
	sIns     map[uint64]disasm2.Text
	sInsList []uint64

	// id assigned for external symbol lookup
	sExtSymLastOff  uint64
	sExtSym         map[uint64]string
	sExtSymOffOrder []uint64
	sLabelSym       map[uint64]string
	sComment        map[uint64]string // comment on instr

	cfg    *conf.Config
	hdr    hdr.Hdr
	sFnHdr map[uint64]*ast.FuncDecl
}

func New(cfg *conf.Config, o *elf.File) (st *LinkState, err error) {
	if o == nil {
		err = fmt.Errorf("link/elf: empty elf file")
		return
	}
	st = &LinkState{}
	st.File = o
	st.cfg = cfg

	st.sProgSectionLoc = map[elf.SectionIndex][2]uint64{}

	st.sBaseAddr = 0x0

	st.sFn = map[uint64][]byte{}
	st.sFnStackSz = map[uint64]uint64{}
	st.sFnName = map[uint64]string{}
	st.sFnSize = map[uint64]uint64{}

	st.sIns = map[uint64]disasm2.Text{}

	st.sExtSym = map[uint64]string{}

	st.sLabelSym = map[uint64]string{}
	st.sComment = map[uint64]string{}

	st.sFnHdr = map[uint64]*ast.FuncDecl{}

	if err = st.init(); err != nil {
		return
	}
	return
}

func (st *LinkState) init() (err error) {
	st.Arch, err = st.archIdent()
	if err != nil {
		return
	}
	// load text section
	err = st.loadProgbitSections()
	if err != nil {
		return
	}
	// parse symbols
	st.sSymbols, err = st.File.Symbols()
	if err != nil {
		return
	}
	// load FUNC symbol
	err = st.loadSymFunc()
	if err != nil {
		return
	}

	// load header
	err = st.parseHeader()
	if err != nil {
		return
	}

	// load relocation
	err = st.getRelocation()
	if err != nil {
		return
	}

	// do disasm and fix addressing
	err = st.doDisasm()
	if err != nil {
		return
	}
	return
}

func (st *LinkState) archIdent() (r string, err error) {
	hdr := st.File.FileHeader
	switch {
	case hdr.Class == elf.ELFCLASS32 && hdr.Machine == elf.EM_386:
		r = "386"
		return
	case hdr.Class == elf.ELFCLASS64 && hdr.Machine == elf.EM_X86_64:
		r = "amd64"
		return
	case hdr.Class == elf.ELFCLASS64 && hdr.Machine == elf.EM_AARCH64:
		r = "arm64"
		return
	}
	return "", fmt.Errorf("arch is not supported atm.")
}

func (st *LinkState) parseHeader() (err error) {
	// open header file
	var f *os.File
	var bb []byte
	f, err = os.Open(st.cfg.StubFile)
	if err != nil {
		return
	}
	defer f.Close()
	bb, err = io.ReadAll(f)
	if err != nil {
		return
	}
	st.hdr, err = hdr.ParseFile(st.cfg.StubFile, string(bb), st.Arch)
	if err != nil {
		return
	}

	for _, fn := range st.hdr.GetFuncDecls(false) {
		astFnName := fn.Name.Name
		if astFnName == "native_entry" {
			err = fmt.Errorf("reserved func name: %s", astFnName)
			return
		}
		var found = false
		for off, nm := range st.sFnName {
			if nm == astFnName {
				st.sFnHdr[off] = fn
				found = true
				break
			}
		}
		if !found {
			err = fmt.Errorf("func header is not used: %q, have %+#v", astFnName, st.sFnName)
			return
		}
	}
	return
}

func align8(addr uint64) uint64 {
	return (((addr - 1) >> 3) + 1) << 3
}

func (st *LinkState) registerFunc(off uint64, sz uint64, name string) {
	st.sFnSize[off] = sz
	st.sFnOrder = append(st.sFnOrder, off)

	if _, exist := st.sFn[off]; exist {
		panic(fmt.Sprintf("attempting to replace known off=%x name=%s sz=%d", off, name, sz))
	}
	st.sFn[off] = st.sProgData[off : off+sz] // !! ref from ProgData
	st.sFnName[off] = name
}

func (st *LinkState) registerEntrypoint(fnName string, code []byte) {
	off := st.sFnLastOff
	sz := uint64(len(code))
	st.sProgData = append(st.sProgData, code...)

	// st.sFnSize[off] = sz
	// st.sFnOrder = append(st.sFnOrder, off)
	// st.sFn[off] = st.sProgData[off : off+sz]
	// st.sFnName[off] = fnName
	st.registerFunc(off, sz, fnName)
	//
	st.sFnLastOff = off + sz
}

func (st *LinkState) loadSymFunc() (err error) {
	syms, idx := st.getSymbolsOnSection(".text")
	if len(syms) < 1 {
		err = fmt.Errorf("no FUNC symbol at all")
		return
	}

	txtEndOff := st.sProgSectionLoc[idx][1]
	_ = txtEndOff

	for i, sym := range syms {
		_ = i
		symSize := sym.Size

		// !! base addr + sym off
		start := st.sBaseAddr + sym.Value
		end := start + symSize

		// get next syms
		// if i+1 <= len(syms) {
		// 	nextSym := syms[i+1]
		// 	nextStart := st.sBaseAddr + nextSym.Value
		// 	symSize = nextStart - start
		// 	end = start + symSize
		// }
		// !! align 8
		// if end < txtEndOff {
		// 	symSize = align8(sym.Size)
		// 	end = start + symSize
		// }

		// ignore empty code.
		if end-start < 1 {
			continue
		}

		st.sFnOrder = append(st.sFnOrder, start)
		st.sFnName[start] = sym.Name
		st.sFnSize[start] = symSize

		// refer from text data, do NOT copy.
		st.sFn[start] = st.sProgData[start:end]
	}

	// ascending sym func offset
	slices.Sort(st.sFnOrder)

	// fix function padding
	for i, fnOff := range st.sFnOrder {
		if i+1 < len(st.sFnOrder) {
			nextFnOff := st.sFnOrder[i+1]
			sz := nextFnOff - fnOff
			end := fnOff + sz
			st.sFnSize[fnOff] = sz
			st.sFn[fnOff] = st.sProgData[fnOff:end]
		}
	}

	// check overlapping offset, and gap
	var lastFnOff uint64 = 0
	_ = lastFnOff
	for _, fnAddr := range st.sFnOrder {
		curOff := fnAddr + st.sFnSize[fnAddr]
		// if fnAddr < lastFnOff { // overlap with top FUNC
		// return fmt.Errorf("FUNC overlapping: lastSegOff: %x, curOff: %x", lastFnOff, curOff)
		// }
		// check FUNC gap
		// if (fnAddr - lastFnOff) != 0 {
		// tbd..
		// }
		lastFnOff = curOff
	}
	st.sFnLastOff = lastFnOff
	return
}

func (st *LinkState) getSymbolsOnSection(sectionName string) (syms []elf.Symbol, idx elf.SectionIndex) {
	for i, sect := range st.File.Sections {
		if sect.Name == sectionName {
			// find sym that matched with the section.
			for _, sym := range st.sSymbols {
				if sym.Section == elf.SectionIndex(i) {
					syms = append(syms, sym)
				}
			}
			idx = elf.SectionIndex(i)
			break
		}
	}
	return
}

func (st *LinkState) archNop(sz int) []byte {
	switch st.Arch {
	case "amd64":
		return disasm2.ArchAMD64.Nop(sz)
	}
	panic("unsupported nop arch")
}

func (st *LinkState) loadProgbitSections() (err error) {
	// !! load entrypoint, and add the base addr
	err = st.loadEntrypoint()
	if err != nil {
		return
	}

	// !! add off with base
	// var off = st.sBaseAddr
	var progbitStartOff uint64 = 0
	for i, s := range st.File.Sections {
		if s.Type != elf.SHT_PROGBITS {
			continue
		}
		if s.Flags&elf.SHF_ALLOC == 0 {
			continue
		}
		if progbitStartOff == 0 {
			progbitStartOff = s.Offset
		}

		off := uint64(int64(st.sBaseAddr) + int64(s.Offset) - int64(progbitStartOff))

		if toAlign := off % s.Addralign; toAlign != 0 {
			szNop := s.Addralign - toAlign
			nops := st.archNop(int(szNop))
			psuFnName := fmt.Sprintf("__%s_aligner%d_%d__%d",
				st.cfg.NativeEntryName,
				s.Addralign, szNop, off)
			st.registerFunc(off, szNop, psuFnName)
			st.sProgData = append(st.sProgData, nops...)
			if s.Name == ".text" {
				st.sBaseAddr += szNop
			}
		}

		off = uint64(int64(st.sBaseAddr) + int64(s.Offset) - int64(progbitStartOff))
		// println(delta)

		sectID := elf.SectionIndex(i)

		var dat []byte
		dat, err = s.Data()
		if err != nil {
			return
		}

		st.sProgSection = append(st.sProgSection, sectID)
		// uint64(len(dat)) // or maybe s.Size?
		st.sProgData = append(st.sProgData, dat...)

		sz := uint64(s.Size)

		end := off + sz
		st.sProgSectionLoc[sectID] = [2]uint64{off, end}

		// align
		// if len(dat)%8 != 0 {
		// 	rem := align8(uint64(len(dat))) - uint64(len(dat))
		// 	dat = append(dat, make([]byte, rem)...)
		// }

		// if s.Name == ".text" {
		// 	end++
		// }
		// off = end + 1
	}

	// !! address external sym out of progbit size
	st.sExtSymLastOff = uint64(len(st.sProgData))

	return
}

// get remaining program data based on sFnLastOff
func (st *LinkState) getRemainingProgData() []byte {
	return st.sProgData[st.sFnLastOff:]
}
