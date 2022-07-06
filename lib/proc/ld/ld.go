package ld

import (
	"fmt"
	"strings"

	"github.com/ii64/golinker/lib/proc"
)

var DEFAULT_LD = "ld"

type Ld struct {
	p *proc.Process
}

func New(args []string, files []string) (*Ld, error) {
	l := &Ld{}
	files, err := l.checkFilesContainsOpts(files)
	if err != nil {
		return nil, err
	}
	l.p = proc.New(DEFAULT_LD, append(args, files...))
	return l, nil
}

func (*Ld) checkFilesContainsOpts(args []string) ([]string, error) {
	var file string
	for _, file = range args {
		if strings.HasPrefix(file, "-") {
			goto InvalidFilename
		}
		switch file {
		case "-o":
			goto InvalidFilename
		}
	}
	return args, nil
InvalidFilename:
	return nil, fmt.Errorf("disallowed %q", file)
}

func (l *Ld) Process() *proc.Process {
	return l.p
}
