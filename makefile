FALCOSECURITY_LIBSCAP_DIR=$(realpath ../libs/userspace/libscap)
SHELL=/bin/bash -o pipefail

GO ?= go

PLUGINS_CGO_INCLUDE=CGO_CFLAGS="-I=$(FALCOSECURITY_LIBSCAP_DIR)"


.PHONY: examples/dummy
examples/dummy:
	GODEBUG=cgocheck=2 $(PLUGINS_CGO_INCLUDE) $(GO) build -buildmode=c-shared -o $@/libdummy.so $@/*.go

.PHONY: examples/async
examples/async:
	GODEBUG=cgocheck=2 $(PLUGINS_CGO_INCLUDE) $(GO) build -buildmode=c-shared -o $@/libasync.so $@/*.go

.PHONY: examples/batch
examples/batch:
	GODEBUG=cgocheck=2 $(PLUGINS_CGO_INCLUDE) $(GO) build -buildmode=c-shared -o $@/libbatch.so $@/*.go
