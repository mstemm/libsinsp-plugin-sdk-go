SHELL=/bin/bash -o pipefail

GO ?= go

all: libbatch.so

.PHONY: libbatch.so
libbatch.so:
	GODEBUG=cgocheck=2 $(GO) build -buildmode=c-shared -o libbatch.so *.go

