NAME=quirktiva
BINDIR=bin
VERSION=$(shell git describe --tags --always || echo "unknown version")
BUILDTIME=$(shell date -u +'%FT%TZ')
GOBUILD=CGO_ENABLED=0 go build -trimpath -ldflags '-X "github.com/yaling888/quirktiva/constant.Version=$(VERSION)" \
		-X "github.com/yaling888/quirktiva/constant.BuildTime=$(BUILDTIME)" \
		-w -s -buildid='

PLATFORM_LIST = \
	darwin-amd64 \
	darwin-amd64-v3 \
	darwin-arm64 \
	linux-386 \
	linux-amd64 \
	linux-amd64-v3 \
	linux-armv5 \
	linux-armv6 \
	linux-armv7 \
	linux-arm64 \
	linux-mips-softfloat \
	linux-mips-softfloat-without-gvisor \
	linux-mips-hardfloat \
	linux-mips-hardfloat-without-gvisor \
	linux-mipsle-softfloat \
	linux-mipsle-softfloat-without-gvisor \
	linux-mipsle-hardfloat \
	linux-mipsle-hardfloat-without-gvisor \
	linux-mips64 \
	linux-mips64-without-gvisor \
	linux-mips64le \
	linux-mips64le-without-gvisor \
	linux-riscv64 \
	linux-loong64 \
	freebsd-386 \
	freebsd-amd64 \
	freebsd-amd64-v3 \
	freebsd-arm64

WINDOWS_ARCH_LIST = \
	windows-386 \
	windows-amd64 \
	windows-amd64-v3 \
	windows-arm64 \
	windows-armv7

all: linux-amd64 darwin-amd64 windows-amd64 # Most used

docker:
	$(GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-amd64:
	GOARCH=amd64 GOOS=darwin $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-amd64-v3:
	GOARCH=amd64 GOOS=darwin GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-amd64-v3-without-gvisor:
	GOARCH=amd64 GOOS=darwin GOAMD64=v3 $(GOBUILD) -tags nogvisor -o $(BINDIR)/$(NAME)-$@

darwin-amd64-v3-without-hysteria2:
	GOARCH=amd64 GOOS=darwin GOAMD64=v3 $(GOBUILD) -tags nohy2 -o $(BINDIR)/$(NAME)-$@

darwin-amd64-v3-without-hysteria2-gvisor:
	GOARCH=amd64 GOOS=darwin GOAMD64=v3 $(GOBUILD) -tags nohy2,nogvisor -o $(BINDIR)/$(NAME)-$@

darwin-arm64:
	GOARCH=arm64 GOOS=darwin $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-386:
	GOARCH=386 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64:
	GOARCH=amd64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64-v3:
	GOARCH=amd64 GOOS=linux GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-armv5:
	GOARCH=arm GOOS=linux GOARM=5 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-armv6:
	GOARCH=arm GOOS=linux GOARM=6 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-armv7:
	GOARCH=arm GOOS=linux GOARM=7 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-arm64:
	GOARCH=arm64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips-softfloat:
	GOARCH=mips GOMIPS=softfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips-softfloat-without-gvisor:
	GOARCH=mips GOMIPS=softfloat GOOS=linux $(GOBUILD) -tags nogvisor -o $(BINDIR)/$(NAME)-$@

linux-mips-hardfloat:
	GOARCH=mips GOMIPS=hardfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips-hardfloat-without-gvisor:
	GOARCH=mips GOMIPS=hardfloat GOOS=linux $(GOBUILD) -tags nogvisor -o $(BINDIR)/$(NAME)-$@

linux-mipsle-softfloat:
	GOARCH=mipsle GOMIPS=softfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mipsle-softfloat-without-gvisor:
	GOARCH=mipsle GOMIPS=softfloat GOOS=linux $(GOBUILD) -tags nogvisor -o $(BINDIR)/$(NAME)-$@

linux-mipsle-hardfloat:
	GOARCH=mipsle GOMIPS=hardfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mipsle-hardfloat-without-gvisor:
	GOARCH=mipsle GOMIPS=hardfloat GOOS=linux $(GOBUILD) -tags nogvisor -o $(BINDIR)/$(NAME)-$@

linux-mips64:
	GOARCH=mips64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips64-without-gvisor:
	GOARCH=mips64 GOOS=linux $(GOBUILD) -tags nogvisor -o $(BINDIR)/$(NAME)-$@

linux-mips64le:
	GOARCH=mips64le GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips64le-without-gvisor:
	GOARCH=mips64le GOOS=linux $(GOBUILD) -tags nogvisor -o $(BINDIR)/$(NAME)-$@

linux-riscv64:
	GOARCH=riscv64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-loong64:
	GOARCH=loong64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

freebsd-386:
	GOARCH=386 GOOS=freebsd $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

freebsd-amd64:
	GOARCH=amd64 GOOS=freebsd $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

freebsd-amd64-v3:
	GOARCH=amd64 GOOS=freebsd GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

freebsd-arm64:
	GOARCH=arm64 GOOS=freebsd $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

windows-386:
	GOARCH=386 GOOS=windows $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64:
	GOARCH=amd64 GOOS=windows $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64-v3:
	GOARCH=amd64 GOOS=windows GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-arm64:
	GOARCH=arm64 GOOS=windows $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-armv7:
	GOARCH=arm GOOS=windows GOARM=7 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

gz_releases=$(addsuffix .gz, $(PLATFORM_LIST))
zip_releases=$(addsuffix .zip, $(WINDOWS_ARCH_LIST))

$(gz_releases): %.gz : %
	chmod +x $(BINDIR)/$(NAME)-$(basename $@)
	gzip -f -S -$(VERSION).gz $(BINDIR)/$(NAME)-$(basename $@)

$(zip_releases): %.zip : %
	zip -m -j $(BINDIR)/$(NAME)-$(basename $@)-$(VERSION).zip $(BINDIR)/$(NAME)-$(basename $@).exe

all-arch: $(PLATFORM_LIST) $(WINDOWS_ARCH_LIST)

releases: $(gz_releases) $(zip_releases)

vet:
	go test ./...

lint_os_list := darwin windows linux freebsd openbsd

lint: $(foreach os,$(lint_os_list),$(os)-lint)
%-lint:
	GOOS=$* golangci-lint run ./...

lint-fix: $(foreach os,$(lint_os_list),$(os)-lint-fix)
%-lint-fix:
	GOOS=$* golangci-lint run --fix ./...

clean:
	rm -rf $(BINDIR)/*

CLANG ?= clang-14
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

ebpf: export BPF_CLANG := $(CLANG)
ebpf: export BPF_CFLAGS := $(CFLAGS)
ebpf:
	cd component/ebpf/ && go generate ./...
