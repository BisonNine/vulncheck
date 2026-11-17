# vulncheck
#
# What it is: govulncheck with an ignore list. It runs the govulncheck found
# on the PATH and fails when the scanned code calls a vulnerable function.
#
# What it is for: one vulnerability check shared by every project, used from
# a project's own "make test":
#
#     govulncheck:
#     	@go run go.bison9.com/vulncheck/cmd/vulncheck@latest .
#
# Temporary exceptions: a vulnerability with no fixed release can be excused
# for a limited time in the project's b9.yaml:
#
#     govulncheck:
#       enabled: true
#       ignore:
#         - id: GO-2026-0001              # the ID vulncheck printed
#           reason: no fixed release yet  # required
#           until: 20261231               # last day it is excused
#
# After that day the check fails again. Remove the entry once the dependency
# is fixed. README.md has the full rules.
#
# This Makefile builds and tests vulncheck itself. make is the standard build
# interface: make (test, then build), test, build, clean, install, uninstall,
# lint, fmt, vet and update.

BINARY_NAME = vulncheck
BUILD_DIR   = bin

GIT_COMMIT=$(shell git rev-parse --short=8 HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GO_VERSION=$(shell go version | awk '{print $$3}')
# UTC so it always increases; := so one run stamps one number.
BUILD_NUMBER:=$(shell date -u +%Y%m%d%H%M%S)
APP_PKG=go.bison9.com/vulncheck/app
LDFLAGS=-ldflags "-X $(APP_PKG).gitCommit=$(GIT_COMMIT) -X $(APP_PKG).buildTime=$(BUILD_TIME) -X $(APP_PKG).goVersion=$(GO_VERSION) -X $(APP_PKG).buildNumber=$(BUILD_NUMBER) -s -w"

.PHONY: all test build clean install uninstall lint fmt vet update

all: test
	$(MAKE) build

test:
	./test.sh

build:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -trimpath $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/vulncheck

clean:
	rm -rf $(BUILD_DIR)
	go clean -testcache

# Root installs to /usr/local/bin; anyone else to an existing ~/bin.
install: build
	@if [ "$$(id -u)" = "0" ]; then dest=/usr/local/bin; \
	elif [ -d "$$HOME/bin" ]; then dest="$$HOME/bin"; \
	else echo "No ~/bin: use sudo make install for a system install, or create ~/bin for a personal one." >&2; exit 1; fi; \
	install -m 0755 $(BUILD_DIR)/$(BINARY_NAME) "$$dest/$(BINARY_NAME)" && echo "Installed $$dest/$(BINARY_NAME)"

uninstall:
	@if [ "$$(id -u)" = "0" ]; then dest=/usr/local/bin; else dest="$$HOME/bin"; fi; \
	if [ -e "$$dest/$(BINARY_NAME)" ]; then rm -f "$$dest/$(BINARY_NAME)" && echo "Removed $$dest/$(BINARY_NAME)"; \
	else echo "Not installed in $$dest"; fi

lint:
	golangci-lint run ./...

fmt:
	golangci-lint fmt ./...

vet:
	go vet ./...

update:
	go get -u ./...
	go mod tidy
