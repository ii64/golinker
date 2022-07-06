package hdr

var archBit64 = map[string]uint64{
	"byte": 1,
	"bool": 1,
	"rune": 4,

	// use fp register.
	// "float32": 4,
	// "float64": 8,

	"int":   8,
	"int8":  1,
	"int16": 2,
	"int32": 4,
	"int64": 8,

	"uint":    8,
	"uint8":   1,
	"uint16":  2,
	"uint32":  4,
	"uint64":  8,
	"uintptr": 8,

	"string":         8 * 2,
	"ptr":            8,
	"unsafe.Pointer": 8,
	"syscall.Errno":  8,
	"array":          8 * 3,
	"any":            8 * 2,
}

var archTypeSize = map[string]map[string]uint64{
	"arm64": archBit64,
	"amd64": archBit64,
}
