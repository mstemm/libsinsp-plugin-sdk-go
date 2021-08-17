SHELL=/bin/bash -o pipefail

GO ?= go

all: libdummy.so

.PHONY: libdummy.so
libdummy.so:
	GODEBUG=cgocheck=2 $(GO) build -buildmode=c-shared -o libdummy.so *.go

