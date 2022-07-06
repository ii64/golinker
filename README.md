# golinker

### A tiny "linker" that generate Go Plan9 ASM

Currently the linker only support `ELF` object and it must be position independent.

"Compile once, and get the machine code!"

Tested for `amd64`, planned to support `arm64`.

## Install

Capstone engine: https://github.com/capstone-engine/capstone

```bash
go install github.com/ii64/golinker@latest
```

Or clone first, and do:

```bash
make build-debug
```

## Example

- https://github.com/ii64/test-golinker (SIMD)
- https://github.com/ii64/gouringasm (Syscall io_uring, liburing 2.1)

## Related

- https://dave.cheney.net/2016/01/18/cgo-is-not-go
- https://github.com/chenzhuoyu/asm2asm
- https://github.com/FiloSottile/ed25519-dalek-rustgo
- https://github.com/golang/go/issues/28152
- https://github.com/ii64/test-cgo-direct
## License

This project is released under [Apache-2.0](./LICENSE).