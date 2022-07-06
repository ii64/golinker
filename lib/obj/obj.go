package obj

import "debug/elf"

type Object struct {
	Elf *elf.File
}
