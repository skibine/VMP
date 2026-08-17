# region MAKEFILE [DOMAIN(7): Build; CONCEPT(7): Automation; TECH(7): make]
# GREP_SUMMARY: make, build, test, vet, run, tidy, scaffold
# STRUCTURE: ▶ target → ○ go build/test/vet → ⎷ artifact

GO ?= go
PKG := ./...
BIN := vmpulse
WEB := web

# Hardening flags for the release binaries. Stripping symbols/debug, trimming absolute build
# paths, not embedding VCS status and removing the Go buildid all shrink the surface that AV
# heuristics (e.g. Windows Defender "Trojan:Win32/Bearfoos.Alml") use to flag unsigned Go
# binaries with network + command-execution features. Signing is still required for clean
# distribution, but these flags reduce false-positive detections significantly.
LDFLAGS := -s -w -buildid=
BUILDFLAGS := -trimpath -buildvcs=false
# Version stamp injected into main.Version. "git describe" yields the nearest tag (or the short SHA
# with --always), suffixed -dirty for uncommitted changes; falls back to "dev" outside a git repo.
# No spaces, so the -X value needs no quoting (nested quotes would break the outer -ldflags '...').
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)-$(shell date +%Y%m%d-%H%M)
LDFLAGS += -X main.Version=$(VERSION)

.PHONY: all build web vet test run tidy clean test-loop web-dev build-windows

all: vet test build

# Build the SPA into internal/web/dist (embedded by the Go binary).
web:
	cd $(WEB) && npm install && npm run build

web-dev:
	cd $(WEB) && npm run dev

build: web
	$(GO) build $(BUILDFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/vmpulse

# Cross-compile a hardened Windows amd64 binary (pure-Go deps, no CGO) into dist/.
build-windows: web
	mkdir -p dist
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(BUILDFLAGS) -ldflags '$(LDFLAGS)' -o dist/vmpulse-windows-amd64.exe ./cmd/vmpulse

vet:
	$(GO) vet $(PKG)

test:
	$(GO) test $(PKG) -v

# Anti-Loop runner: tracks failed attempts in tests/.test_counter.json, resets on 100% PASS.
test-loop:
	@bash scripts/run_tests.sh

run: build
	./$(BIN) -config config.yaml

tidy:
	$(GO) mod tidy

clean:
	rm -f $(BIN) coverage.out
	rm -rf dist/ data/ logs/
