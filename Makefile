GIT ?= git
GO_VARS ?=
GO ?= go
COMMIT := $(shell $(GIT) rev-parse HEAD)
VERSION ?= $(shell $(GIT) describe --tags ${COMMIT} 2> /dev/null || echo "$(COMMIT)")
BUILD_TIME := $(shell LANG=en_US date +"%F_%T_%z")
ROOT := rcvr
LD_FLAGS := -X $(ROOT).Version=$(VERSION) -X $(ROOT).Commit=$(COMMIT) -X $(ROOT).BuildTime=$(BUILD_TIME)

.PHONY: help clean dependencies test
help:
	@echo "Please use \`make <ROOT>' where <ROOT> is one of"
	@echo "  dependencies to go install the dependencies"
	@echo "  rcvrsmtp to build the main binary for current platform"
	@echo "  test         to run unittests"

clean:
	rm -f rcvrdmarcd

dependencies:
	$(GO_VARS) $(GO) get ./...

rcvrdmarcd: */*.go
	$(GO_VARS) $(GO) build -o="rcvrdmarcd" -ldflags="$(LD_FLAGS)" $(ROOT)/cmd

test: */*.go
	$(GO_VARS) $(GO) test -v $(ROOT)