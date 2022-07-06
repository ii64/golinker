package cmd

import (
	"fmt"
	"os"
	"path"

	"github.com/ii64/golinker/conf"
	"github.com/ii64/golinker/lib/link"
	"github.com/ii64/golinker/lib/obj"
	"github.com/ii64/golinker/lib/proc/ld"
)

func Main(cfg *conf.Config) (err error) {
	// Note: WIP support PIC first

	// create temporary directory
	cfg.TempDir, err = os.MkdirTemp(os.TempDir(), "golinker_*")
	if err != nil {
		return
	}

	defer func() {
		// delete temp dir
		errx := os.RemoveAll(cfg.TempDir)
		if errx != nil {
			fmt.Fprintf(os.Stderr, "error: remove tempdir %s", err)
		}
	}()

	var objFiles = cfg.ObjFiles
	if len(cfg.ArFiles) > 0 {
		var mergedObjPath string
		if mergedObjPath, err = mergeArToSingleObject(cfg); err != nil {
			return
		}
		objFiles = append(objFiles, mergedObjPath)
	}

	var objFile string
	if objFile, err = mergeToSingleObject(cfg, objFiles); err != nil {
		return
	}

	var o *obj.Object
	o, err = obj.ReadFile(objFile)
	if err != nil {
		return
	}

	var st *link.LinkState
	st, err = link.Link(cfg, o)
	if err != nil {
		return
	}

	_ = st
	return
}

func mergeToSingleObject(cfg *conf.Config, objs []string) (objTemp string, err error) {
	objTemp = path.Join(cfg.TempDir, "all.o")
	var ins *ld.Ld
	ins, err = ld.New([]string{
		"--relocatable",
		"-o", objTemp,
	}, objs)
	if err != nil {
		return
	}

	proc := ins.Process()
	if err = proc.Start(); err != nil {
		return
	}
	var stat *os.ProcessState
	for {
		stat, err = proc.Process.Wait()
		if err != nil {
			return
		}

		if stat.Exited() {
			break
		}
	}
	switch stat.ExitCode() {
	case 0:
	default:
		err = fmt.Errorf("Exec not OK")
	}
	return
}

func mergeArToSingleObject(cfg *conf.Config) (objTemp string, err error) {
	objTemp = path.Join(cfg.TempDir, "ext.o")
	var ins *ld.Ld
	ins, err = ld.New([]string{
		"--relocatable", "--whole-archive",
		"-o", objTemp,
	}, cfg.ArFiles)
	if err != nil {
		return
	}

	proc := ins.Process()
	if err = proc.Start(); err != nil {
		return
	}
	var stat *os.ProcessState
	for {
		stat, err = proc.Process.Wait()
		if err != nil {
			return
		}
		if stat.Exited() {
			break
		}
	}
	return
}
