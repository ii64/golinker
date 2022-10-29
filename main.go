package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ii64/golinker/cmd"
	"github.com/ii64/golinker/conf"
)

func _main(args []string) {
	var err error
	var exitCode int
	cfg := conf.Default()
	fs := cfg.FlagSet("golinker", flag.ExitOnError)
	oldUsage := fs.Usage
	fs.Usage = func() {
		oldUsage()
		fs.PrintDefaults()
		exitCode = 0
		os.Exit(exitCode)
	}
	err = fs.Parse(args)
	if err != nil {
		goto Exit
	}
	err = cfg.Vaildate()
	if err != nil {
		goto Exit
	}
	err = cmd.Main(cfg)
	if err != nil {
		goto Exit
	}
Exit:
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n\n", err)
		fs.Usage()
		exitCode = 1
	}
	os.Exit(exitCode)
}

func main() {
	_main(os.Args[1:])
	// _main([]string{
	// 	// "-extld=ld",
	// 	// "-out=./_example/internal/native",
	// 	"-out=./_sample/_exp/go/hdr",
	// 	// "-stub=./_example/internal/native/stub.go",
	// 	// "-stub=./_sample/_exp/go/hdr/hdr.go",
	// 	"-stub=./_sample/_exp/go/hdr/uring.go",

	// 	// "-entryname=__native_entry2__",
	// 	"-fallback-rawbytes-x86",
	// 	// "-rawbytes-x86",
	// 	"-extsymstub",

	// 	// "./_sample/_exp/libexp-amd64.a",
	// 	// "./_example/native/libnative-amd64.a",
	// 	"/usr/lib/liburing.a",

	// 	// "-extld=aarch64-linux-gnu-ld",
	// 	// "./_sample/_exp/libexp-arm64.a",
	// })
}
