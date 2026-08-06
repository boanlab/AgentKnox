# SPDX-License-Identifier: Apache-2.0
GO      ?= go
BINDIR  := bin

# Single source of truth for the release version. The image tag carries the `v`
# prefix to match the git tag; the Debian version drops it, since dpkg orders
# versions numerically and a leading letter breaks that.
VERSION ?= v0.1.0
TAG     ?= $(VERSION)

IMAGE   ?= boanlab/agentknox
GOLANGCI := $(shell command -v golangci-lint 2>/dev/null || echo $(shell go env GOPATH)/bin/golangci-lint)
GOSEC    := $(shell command -v gosec 2>/dev/null || echo $(shell go env GOPATH)/bin/gosec)

DEB_VERSION ?= $(patsubst v%,%,$(VERSION))
DEB        := dist/agentknox_$(DEB_VERSION)_amd64.deb

.PHONY: all bpf proto build agentknox akctl aggregator offsetdb test vet fmt gofmt golangci-lint gosec build-image push-image deb deb-package tidy clean run

all: build

## bpf: compile the eBPF object (needs clang + llvm-strip); embedded via go:embed.
bpf:
	$(MAKE) -C bpf

## proto: (re)generate gRPC stubs from protobuf/agentknox.proto (needs protoc +
## protoc-gen-go, protoc-gen-go-grpc on PATH). Generated code is committed.
proto:
	protoc --go_out=. --go_opt=module=github.com/boanlab/agentknox \
	       --go-grpc_out=. --go-grpc_opt=module=github.com/boanlab/agentknox \
	       protobuf/agentknox.proto

## build: bpf + userspace binaries.
build: bpf fmt vet agentknox akctl aggregator

agentknox:
	CGO_ENABLED=0 $(GO) build -ldflags "-X main.version=$(TAG)" -o $(BINDIR)/agentknox ./cmd/agentknox

akctl:
	CGO_ENABLED=0 $(GO) build -o $(BINDIR)/akctl ./cmd/akctl

## aggregator: the central event-collection service (separate deployment).
aggregator:
	CGO_ENABLED=0 $(GO) build -o $(BINDIR)/agentknox-aggregator ./cmd/agentknox-aggregator

## offsetdb: (re)generate the build-id -> TLS offset DB from reference builds.
offsetdb:
	$(GO) run ./cmd/agentknox offsetdb --out $(or $(OUT),/etc/agentknox/offsetdb) || true

test:
	$(GO) test ./... -count=1

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./... >/dev/null

## gofmt: CI check — fails if any Go file is not gofmt-clean.
gofmt:
	@out=$$(gofmt -l $$(find . -name '*.go' -not -name '*_bpfel*')); \
	if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; exit 1; fi

## golangci-lint: run the linter (config in .golangci.yml).
golangci-lint:
	$(GOLANGCI) run ./...

## gosec: security scanner over the Go source. Excluded rules are structural
## false positives for a root monitoring daemon:
##   G115/G109 int conversions — bounded pid/hash/offset values.
##   G304/G703 file access / path taint — AgentKnox intentionally reads target
##     binaries, agent-written files, /proc, and config by path; there is no
##     sandbox to escape. These are the tool's purpose, not vulnerabilities.
## -exclude-generated skips files carrying the `Code generated ... DO NOT EDIT.`
## marker: the protoc output under protobuf/agentknoxpb trips G103 on the
## unsafe.Slice/unsafe.StringData that protoc-gen-go emits for the raw
## descriptor. That code is not ours to change, and suppressing G103 repo-wide
## instead would blind the scan to hand-written unsafe use.
GOSEC_EXCLUDE := G115,G109,G304,G703
gosec:
	$(GOSEC) -exclude-dir=bpf -exclude-generated -exclude=$(GOSEC_EXCLUDE) ./...

## build-image: build the container image (docker deployment). VERSION is passed
## through so `agentknox --version` inside the image matches the tag on it.
build-image:
	docker build --build-arg VERSION=$(TAG) -t $(IMAGE):$(TAG) .

## push-image: publish the container image. Release CI overrides TAG with the
## version tag; a bare run would otherwise push :dev.
## PUSH_LATEST=1 additionally moves :latest onto the same image. Release CI sets
## it only for a final vX.Y.Z tag, so a pre-release publishes its own tag but
## never becomes what a bare `docker pull` hands someone.
push-image: build-image
	docker push $(IMAGE):$(TAG)
	@if [ "$(PUSH_LATEST)" = "1" ]; then \
		echo "docker tag $(IMAGE):$(TAG) $(IMAGE):latest"; \
		docker tag $(IMAGE):$(TAG) $(IMAGE):latest; \
		echo "docker push $(IMAGE):latest"; \
		docker push $(IMAGE):latest; \
	fi

## deb: build a Debian package (systemd service auto-enabled on install).
## Recompiles the eBPF object first, so it needs clang + llvm-strip as well as
## dpkg-deb (Debian/Ubuntu). Override version with DEB_VERSION=x.y.z.
deb: bpf
	$(MAKE) deb-package

## deb-package: assemble the .deb without invoking clang, from the eBPF object
## already committed at internal/sensor/agentknox_bpfel.o. Release CI uses this
## so the package embeds the reviewed, committed object -- the same one the
## container image ships -- rather than whatever a runner-side clang produced.
deb-package: agentknox akctl
	@rm -rf dist/deb && mkdir -p dist
	@root=dist/deb/agentknox; \
	install -D -m0755 bin/agentknox $$root/usr/bin/agentknox; \
	install -D -m0755 bin/akctl     $$root/usr/bin/akctl; \
	install -D -m0644 deployments/systemd/agentknox.service $$root/lib/systemd/system/agentknox.service; \
	sed -i 's|/usr/local/bin/agentknox|/usr/bin/agentknox|' $$root/lib/systemd/system/agentknox.service; \
	install -D -m0644 deployments/agentknox.yaml $$root/etc/agentknox/agentknox.yaml; \
	install -d -m0755 $$root/etc/agentknox/policies; \
	install -D -m0644 deployments/policies/example.yaml $$root/usr/share/doc/agentknox/example-policy.yaml; \
	install -d -m0750 $$root/var/lib/agentknox; \
	install -d -m0755 $$root/DEBIAN; \
	sed 's/@VERSION@/$(DEB_VERSION)/' packaging/deb/control.in > $$root/DEBIAN/control; \
	install -m0644 packaging/deb/conffiles $$root/DEBIAN/conffiles; \
	install -m0755 packaging/deb/postinst  $$root/DEBIAN/postinst; \
	install -m0755 packaging/deb/prerm     $$root/DEBIAN/prerm; \
	install -m0755 packaging/deb/postrm    $$root/DEBIAN/postrm; \
	dpkg-deb --root-owner-group --build $$root $(DEB)
	@echo "built $(DEB)"

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BINDIR)
	$(MAKE) -C bpf clean

## run: run the daemon (needs root for eBPF/LSM).
run: build
	sudo -E $(BINDIR)/agentknox --log-level=debug
