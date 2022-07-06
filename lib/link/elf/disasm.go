package elf

import (
	"fmt"
)

func (st *LinkState) doDisasm() (err error) {
	switch st.Arch {
	case "386":
		return st.doDisasm386()
	case "amd64":
		return st.doDisasmAMD64()
	case "arm64":
		return st.doDisasmARM64()
	}
	return fmt.Errorf("unsupported arch disasm")
}
