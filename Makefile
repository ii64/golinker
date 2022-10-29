all:


install-dep:
	go install github.com/ii64/go-bootstrap@latest

build:
	go-bootstrap build -v -x main.go

build-debug:
	go-bootstrap build -gcflags="all=-N -l" -x main.go