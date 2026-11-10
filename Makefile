VERSION ?= 0.1.1
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
# Commit time, not wall-clock time: two builds of one commit are identical.
DATE    ?= $(shell TZ=UTC0 git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)
GOOS    ?= linux
GOARCH  ?= amd64
LDFLAGS  = -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
GOFLAGS  = -trimpath -buildvcs=false
EXE      = $(if $(filter windows,$(GOOS)),.exe,)
BIN      = dist/hcdn-connector-$(GOOS)-$(GOARCH)$(EXE)

# Pinned tool versions (also used by .github/workflows/*.yml).
STATICCHECK_VERSION ?= v0.8.2
GOVULNCHECK_VERSION ?= v1.9.0
NFPM_VERSION        ?= v2.47.0
GO_LICENSES_VERSION ?= v2.0.1
ALLOWED_LICENSES     = Apache-2.0,BSD-2-Clause,BSD-3-Clause,MIT
TARGETS              = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
# Host arch: a make-exported GOARCH=arm64 would build nfpm itself for arm64 (exec format error).
NFPM = GOOS=$(shell go env GOHOSTOS) GOARCH=$(shell go env GOHOSTARCH) go run github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VERSION)

export CGO_ENABLED = 0

.PHONY: all build build-all cross test lint vulncheck licenses fmt package docker clean

all: fmt lint test build

build:
	mkdir -p dist
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/hcdn-connector

build-all:
	$(foreach t,$(TARGETS),$(MAKE) build GOOS=$(word 1,$(subst /, ,$(t))) GOARCH=$(word 2,$(subst /, ,$(t))) &&) true

# Compiles every package (tests included) for every supported target.
cross:
	$(foreach t,$(TARGETS),GOOS=$(word 1,$(subst /, ,$(t))) GOARCH=$(word 2,$(subst /, ,$(t))) go vet ./... &&) true

# -race needs cgo; the exported CGO_ENABLED=0 is for the static binary only.
test:
	CGO_ENABLED=1 go test -race -count=1 ./...

fmt:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "gofmt: files need formatting"; exit 1; }

lint: fmt
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

licenses:
	go run github.com/google/go-licenses/v2@$(GO_LICENSES_VERSION) check ./... --allowed_licenses=$(ALLOWED_LICENSES)

# deb + rpm for GOARCH via nfpm (go run, no install needed). One arch per call.
package: build
	cp $(BIN) dist/hcdn-connector
	VERSION=$(VERSION) NFPM_ARCH=$(GOARCH) $(NFPM) package -f packaging/nfpm.yaml -p deb -t dist/
	VERSION=$(VERSION) NFPM_ARCH=$(GOARCH) $(NFPM) package -f packaging/nfpm.yaml -p rpm -t dist/
	rm -f dist/hcdn-connector

docker:
	docker build -f packaging/Dockerfile --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) -t hcdn-connector:$(VERSION) .

clean:
	rm -rf dist
