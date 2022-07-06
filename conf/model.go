package conf

import (
	"flag"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/ii64/golinker/lib/disasm2"
	"github.com/ii64/golinker/lib/proc/ld"
)

type Config struct {
	// StubFile holding the function signature of ASM function.
	StubFile string

	ObjFiles     []string
	ArFiles      []string
	GenerateOpts string
	OutputDir    string

	ExtLD string

	TempDir string

	NativeEntryName string

	DropRawBytesX86     bool
	RawBytesFallbackX86 bool
	GenExternalSymStub  bool

	fs *flag.FlagSet
}

func Default() *Config {
	return &Config{}
}

func (cfg *Config) GetStubFileBasename() (basename string, ext string) {
	stubFilename := path.Base(cfg.StubFile)
	ext = path.Ext(stubFilename)
	basename = stubFilename[:len(stubFilename)-len(ext)]
	return
}

func (cfg *Config) Vaildate() error {

	if cfg.OutputDir == "" {
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		cfg.OutputDir = dir
	} else {
		cfg.OutputDir = mustAbs(cfg.OutputDir)
	}
	var invalidFile []string
	for _, inp := range cfg.fs.Args() {
		originalFilename := inp
		inp = mustAbs(inp)
		switch {
		case strings.HasSuffix(inp, ".o"):
			if validateFilePath(inp) {
				cfg.ObjFiles = append(cfg.ObjFiles, inp)
				break
			}
			fallthrough
		case strings.HasSuffix(inp, ".a"):
			if validateFilePath(inp) {
				cfg.ArFiles = append(cfg.ArFiles, inp)
				break
			}
			fallthrough
		default:
			invalidFile = append(invalidFile, originalFilename)
		}
	}
	if len(invalidFile) > 0 {
		for _, fn := range invalidFile {
			fmt.Fprintf(os.Stderr, "error: file %q: not .o, .a, or the file is missing.\n", fn)
		}
		return fmt.Errorf("invalid input")
	}

	if len(cfg.ArFiles) < 1 && len(cfg.ObjFiles) < 1 {
		return fmt.Errorf("nothing to do")
	}

	if cfg.ExtLD != "" {
		ld.DEFAULT_LD = cfg.ExtLD
	}

	disasm2.X86JustWriteRawBytes = cfg.DropRawBytesX86
	disasm2.X86RawBytesFallback = cfg.RawBytesFallbackX86
	
	return nil
}
