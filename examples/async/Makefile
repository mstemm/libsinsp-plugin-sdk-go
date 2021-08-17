SHELL=/bin/bash -o pipefail

GO ?= go

all: libasync.so

.PHONY: libasync.so
libasync.so:
	GODEBUG=cgocheck=2 $(GO) build -buildmode=c-shared -o libasync.so *.go

