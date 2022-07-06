package conf

import (
	"os"
	"path/filepath"
)

func mustAbs(p string) string {
	p, err := filepath.Abs(p)
	if err != nil {
		panic(err)
	}
	return p
}

func validateFilePath(p string) bool {
	info, err := os.Stat(p)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return false
	}
	return true
}
