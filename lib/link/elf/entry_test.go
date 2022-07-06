package elf

import (
	"fmt"
	"testing"
)

func TestEntryAMD64(t *testing.T) {
	code, fs := entryAMD64()
	fmt.Printf("--- sz: %d ---\n%+#v\n------\n", len(code), code)
	for _, f := range fs {
		fmt.Printf("%s\n", f)
	}
}
