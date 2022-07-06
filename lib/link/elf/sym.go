package elf

import (
	"fmt"
	"sync/atomic"
)

func (st *LinkState) resolveSymbol2(addr uint64) (name string, base uint64) {
	var exist bool

	// check if addr is a external symbol
	name, exist = st.sExtSym[addr]
	if exist {
		name = name + "(SB)"
		base = addr
		return
	}

	// check if addr is a local func sym
	name, exist = st.sFnName[addr]
	if exist {
		name = fmt.Sprintf("·%s+%d(SB)", st.cfg.NativeEntryName, addr)
		base = addr
		// st.sLabelSym[addr] = fmt.Sprintf("__fn_%d", addr)
		return
	}

	// check if addr is a label
	name, exist = st.sLabelSym[addr]
	if exist {
		base = addr
		return
	}

	// check if addr is part of Ins addr
	_, exist = st.sIns[addr]
	if exist {
		name = fmt.Sprintf("_lbl_%x", addr)
		// register label
		st.sLabelSym[addr] = name
		base = addr
		return
	}

	return "", 0
}

func (st *LinkState) getExtSymID(extSymName string) (off uint64, err error) {
	if extSymName == "" {
		err = fmt.Errorf("external symbol name must be not empty")
		return
	}

	for off, ksymname := range st.sExtSym {
		if ksymname == extSymName {
			return off, nil
		}
	}

	off = atomic.AddUint64(&st.sExtSymLastOff, 1)
	st.sExtSym[off] = extSymName
	st.sExtSymOffOrder = append(st.sExtSymOffOrder, off)
	return off, nil
}

// func (st *LinkState)
