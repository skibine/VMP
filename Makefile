# region MAKEFILE [DOMAIN(7): Build; CONCEPT(7): Automation; TECH(7): make]
# GREP_SUMMARY: make, build, test, vet, run, tidy, scaffold
# STRUCTURE: ▶ target → ○ go build/test/vet → ⎷ artifact

GO ?= go
PKG := ./...
BIN := vmpulse
WEB := web

.PHONY: all build web vet test run tidy clean test-loop web-dev

all: vet test build

# Build the SPA into internal/web/dist (embedded by the Go binary).
web:
	cd $(WEB) && npm install && npm run build

web-dev:
	cd $(WEB) && npm run dev

build: web
	$(GO) build -o $(BIN) ./cmd/vmpulse

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
	rm -rf data/ logs/
