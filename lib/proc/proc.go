package proc

import (
	"os"
	"os/exec"
)

type Process struct {
	*exec.Cmd
}

func New(program string, args []string) *Process {
	p := &Process{}
	p.Cmd = exec.Command(program, args...)
	p.Stdin = Reader{p, os.Stdin}
	p.Stdout = Writer{p, os.Stdout}
	p.Stderr = Writer{p, os.Stderr}
	activeProcess.Add(p)
	return p
}
