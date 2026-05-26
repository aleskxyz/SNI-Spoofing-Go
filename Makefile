# SNI-Spoofing-Go — build targets (see BUILD.md for prerequisites and usage)
#
# Pure Go: CGO_ENABLED=0 everywhere.

LDFLAGS := -s -w
CGO_ENABLED := 0
DIST ?= dist

.PHONY: help all dist clean mod test build \
	windows linux-amd64 linux-arm64 linux-armv7 linux-mipsle linux-mips \
	darwin-amd64 darwin-arm64

# Default: show targets (run `make build` for local binary)
.DEFAULT_GOAL := help

help:
	@echo "SNI-Spoofing-Go"
	@echo ""
	@echo "  make build          Current GOOS/GOARCH -> ./sni-spoofing"
	@echo "  make dist | all     All platforms -> $(DIST)/"
	@echo "  make windows        Windows amd64 -> $(DIST)/sni-spoofing.exe"
	@echo "  make linux-amd64    Linux targets -> $(DIST)/sni-spoofing-linux-*"
	@echo "  make linux-arm64"
	@echo "  make linux-armv7    (GOARM=7)"
	@echo "  make linux-mipsle   (GOMIPS=softfloat)"
	@echo "  make linux-mips     (GOMIPS=softfloat)"
	@echo "  make darwin-amd64   macOS Intel  -> $(DIST)/sni-spoofing-darwin-amd64"
	@echo "  make darwin-arm64   macOS Apple  -> $(DIST)/sni-spoofing-darwin-arm64"
	@echo "  make test           go test ./..."
	@echo "  make mod            go mod download"
	@echo "  make clean          remove $(DIST)/ and ./sni-spoofing"

mod:
	go mod download

test:
	CGO_ENABLED=$(CGO_ENABLED) go test ./...

# Native binary for this machine (name: sni-spoofing)
build:
	CGO_ENABLED=$(CGO_ENABLED) go build -ldflags "$(LDFLAGS)" -o sni-spoofing .

windows:
	@mkdir -p $(DIST)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=windows GOARCH=amd64 \
		go build -ldflags "$(LDFLAGS)" -o $(DIST)/sni-spoofing.exe .

linux-amd64:
	@mkdir -p $(DIST)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 \
		go build -ldflags "$(LDFLAGS)" -o $(DIST)/sni-spoofing-linux-amd64 .

linux-arm64:
	@mkdir -p $(DIST)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=arm64 \
		go build -ldflags "$(LDFLAGS)" -o $(DIST)/sni-spoofing-linux-arm64 .

linux-armv7:
	@mkdir -p $(DIST)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=arm GOARM=7 \
		go build -ldflags "$(LDFLAGS)" -o $(DIST)/sni-spoofing-linux-armv7 .

linux-mipsle:
	@mkdir -p $(DIST)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=mipsle GOMIPS=softfloat \
		go build -ldflags "$(LDFLAGS)" -o $(DIST)/sni-spoofing-linux-mipsle .

linux-mips:
	@mkdir -p $(DIST)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=mips GOMIPS=softfloat \
		go build -ldflags "$(LDFLAGS)" -o $(DIST)/sni-spoofing-linux-mips .

darwin-amd64:
	@mkdir -p $(DIST)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=amd64 \
		go build -ldflags "$(LDFLAGS)" -o $(DIST)/sni-spoofing-darwin-amd64 .

darwin-arm64:
	@mkdir -p $(DIST)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=arm64 \
		go build -ldflags "$(LDFLAGS)" -o $(DIST)/sni-spoofing-darwin-arm64 .

dist all: windows linux-amd64 linux-arm64 linux-armv7 linux-mipsle linux-mips darwin-amd64 darwin-arm64
	@echo "Done. Binaries in $(DIST)/"
	@ls -lh $(DIST)/

clean:
	rm -f sni-spoofing
	rm -f $(DIST)/sni-spoofing.exe $(DIST)/sni-spoofing-linux-amd64 $(DIST)/sni-spoofing-linux-arm64 \
		$(DIST)/sni-spoofing-linux-armv7 $(DIST)/sni-spoofing-linux-mipsle $(DIST)/sni-spoofing-linux-mips \
		$(DIST)/sni-spoofing-darwin-amd64 $(DIST)/sni-spoofing-darwin-arm64
	@-rmdir $(DIST) 2>/dev/null || true
