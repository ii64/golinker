package conf

import (
	"flag"
	"fmt"
	"os"
)

func (c *Config) FlagSet(name string, errorHandling flag.ErrorHandling) *flag.FlagSet {
	fs := flag.NewFlagSet(name, errorHandling)
	c.fs = fs

	fs.StringVar(&c.OutputDir, "out", "", "Output directory")
	fs.StringVar(&c.StubFile, "stub", "", "Stub file holding func signature")

	fs.StringVar(&c.ExtLD, "extld", getDefaultLD(), "External ld")

	fs.StringVar(&c.NativeEntryName, "entryname", "__native_entry__", "Native entry name")

	fs.BoolVar(&c.DropRawBytesX86, "rawbytes-x86", false, "Drop all x86 code as raw bytes")
	fs.BoolVar(&c.RawBytesFallbackX86, "fallback-rawbytes-x86", false, "Drop raw bytes if instruction not found")
	fs.BoolVar(&c.GenExternalSymStub, "extsymstub", false, "Generate external symbol stub")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] ...file.[ao]\n", name)
	}
	return fs
}

func getDefaultLD() string {
	ld := os.Getenv("LD")
	if ld == "" {
		return "ld"
	}
	return ld
}
