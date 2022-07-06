package obj

import (
	"debug/elf"
)

// Note: WIP support ELF.

func ReadFile(path string) (obj *Object, err error) {
	var e *elf.File
	e, err = elf.Open(path)
	if err != nil {
		return
	}
	obj = &Object{
		Elf: e,
	}
	return
}
