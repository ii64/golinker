package disasm2

type SymLookup func(addr uint64) (name string, base uint64)
