package elf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
)

func relInfo32(info uint32) (symNo uint32, typ uint32) {
	return info >> 8, info & 0xff
}

func relaInfo64(info uint64) (symNo uint64, typ uint64) {
	return info >> 32, info & 0xffff
}

func (st *LinkState) getRelocation() (err error) {
	for _, s := range st.File.Sections {
		if s.Type != elf.SHT_RELA && s.Type != elf.SHT_REL {
			continue
		}
		var dat []byte
		dat, err = s.Data()
		if err != nil {
			return
		}
		err = st.loadRelocation(dat, s.Type)
		if err != nil {
			return
		}
	}
	return
}

func (st *LinkState) loadRelocation(dat []byte, sectionType elf.SectionType) (err error) {
	switch st.Arch {
	case "386":
		// 8 is the size of Rel32.
		if len(dat)%8 != 0 {
			return fmt.Errorf("length of relocation section is not a multiple of 8")
		}
		return st.loadRelocation386(dat)
	case "amd64":
		// 24 is the size of Rela64
		if len(dat)%24 != 0 {
			return fmt.Errorf("length of relocation section is not a mutliple of 24")
		}
		return st.loadRelocationAMD64(dat)
	case "arm64":
		// 24 is the size of Rela64
		if len(dat)%24 != 0 {
			return fmt.Errorf("length of relocation section is not a mutliple of 24")
		}
		return st.loadRelocationARM64(dat)
	}
	err = fmt.Errorf("unsupported arch for relocation")
	return
}

func (st *LinkState) loadRelocation386(dat []byte) (err error) {
	b := bytes.NewReader(dat)
	var rel elf.Rel32
	for b.Len() > 0 {
		binary.Read(b, st.File.ByteOrder, &rel)
		symNo, t := relInfo32(rel.Info)
		typ := elf.R_386(t)

		sym := st.sSymbols[symNo-1]
		_ = sym
		switch typ {
		// tbd
		}
	}
	return
}

func (st *LinkState) loadRelocationAMD64(dat []byte) (err error) {
	b := bytes.NewReader(dat)
	var rela elf.Rela64
	for b.Len() > 0 {
		binary.Read(b, st.File.ByteOrder, &rela)
		symNo, t := relaInfo64(rela.Info)
		typ := elf.R_X86_64(t)
		if symNo == 0 || symNo > uint64(len(st.sSymbols)) {
			continue
		}
		sym := st.sSymbols[symNo-1]
		_ = sym

		switch typ {
		case elf.R_X86_64_PLT32, elf.R_X86_64_PC32,

			// !! fix me
			elf.R_X86_64_32, elf.R_X86_64_64:

			// !! add rela off with base
			begin := st.sBaseAddr + rela.Off
			var end int64
			end = int64(begin + 4)

			if typ == elf.R_X86_64_64 {
				end += 4
			}

			// if rela.Addend < 0 {
			// 	end = int64(begin) - rela.Addend
			// } else {
			// 	end = int64(begin) + rela.Addend
			// }
			dat := st.sProgData[begin:end]

			var symOffBegin uint64
			var symOffEnd uint64
			_ = symOffEnd
			if sym.Section == elf.SHN_UNDEF {
				// if sym.Section is SHN_UNDEF (0) then resolve that later
				// therefore make ID as marker for disasm.
				symOffBegin, err = st.getExtSymID(sym.Name)
				if err != nil {
					return
				}
			} else {
				// section begin off + symbol off
				symOffBegin = st.sProgSectionLoc[sym.Section][0] + sym.Value
				symOffEnd = symOffBegin + sym.Size
			}

			// 64 -> 32
			// target off - PC
			var val int64
			if typ == elf.R_X86_64_64 {
				val = int64(st.File.ByteOrder.Uint64(dat))
				val += rela.Addend
			} else if typ == elf.R_X86_64_32 {
				val = int64(st.File.ByteOrder.Uint32(dat))
				val += rela.Addend
			} else {
				val = int64(symOffBegin) + rela.Addend - int64(begin) // - end
			}

			st.File.ByteOrder.PutUint32(dat, uint32(val))
			fmt.Printf("rela off=%x: %s\t| %+#v\t| %+#v\t| %+#v \n", begin, typ,
				dat,
				rela, sym)
		default:
			err = fmt.Errorf("unhandled REL/RELA: %s -> %+#v (symName: %q, sect: %s)", typ, rela, sym.Name, sym.Section)
		}
	}

	return
}

func (st *LinkState) loadRelocationARM64(dat []byte) (err error) {
	b := bytes.NewReader(dat)
	var rela elf.Rela64
	for b.Len() > 0 {
		binary.Read(b, st.File.ByteOrder, &rela)
		symNo, t := relaInfo64(rela.Info)
		typ := elf.R_AARCH64(t)
		if symNo == 0 || symNo > uint64(len(st.sSymbols)) {
			continue
		}
		sym := st.sSymbols[symNo-1]
		_ = sym
		switch typ {
		}

	}

	return
}
