PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
GO ?= go

.PHONY: all check install

all:
	$(GO) build ./cmd/pa-xfer

check:
	$(GO) test ./...
	$(GO) vet ./...
	shellcheck pa pa-export pa-import test

install:
	mkdir -p "$(DESTDIR)$(BINDIR)"
	install -m 0755 pa pa-export pa-import "$(DESTDIR)$(BINDIR)"
	$(GO) build -trimpath -o "$(DESTDIR)$(BINDIR)/pa-xfer" ./cmd/pa-xfer
