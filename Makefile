-include build.mk

.PHONY: all cli lib static shared cross android apple docker test test-ffi test-integration bench install uninstall clean

all: cli lib

cli:
	DESTDIR= $(ZIG) build -p $(OUTDIR) -Doptimize=$(OPTIMIZE) $(ZIGFLAGS)

lib static shared: cli

cross:
	$(ZIG) build cross -Doptimize=$(OPTIMIZE)

android:
	$(ZIG) build android -Doptimize=$(OPTIMIZE)

apple:
	sh scripts/make_xcframework.sh


test:
	$(ZIG) build test

test-ffi:
	$(ZIG) build test-ffi

test-integration:
	$(ZIG) build test-integration

bench:
	$(ZIG) build bench

docker:
	docker build -t $(PROJECT):$(REV_ID) .

install: all
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCDIR) $(DESTDIR)$(CONFDIR)
	install -m 755 $(OUTDIR)/bin/$(PROJECT) $(DESTDIR)$(BINDIR)/$(PROJECT)
	install -m 644 $(OUTDIR)/lib/lib$(PROJECT).a $(DESTDIR)$(LIBDIR)/lib$(PROJECT).a
	install -m 644 include/zeptun.h $(DESTDIR)$(INCDIR)/zeptun.h
	test -f $(DESTDIR)$(CONFDIR)/zeptun.toml || install -m 644 conf/zeptun.toml $(DESTDIR)$(CONFDIR)/zeptun.toml
	install -d $(DESTDIR)$(PREFIX)/lib/systemd/system
	install -m 644 conf/zeptun.service $(DESTDIR)$(PREFIX)/lib/systemd/system/zeptun.service

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(PROJECT)
	rm -f $(DESTDIR)$(LIBDIR)/lib$(PROJECT).a
	rm -f $(DESTDIR)$(INCDIR)/zeptun.h
	rm -f $(DESTDIR)$(PREFIX)/lib/systemd/system/zeptun.service

clean:
	rm -rf $(OUTDIR) .zig-cache libs obj
