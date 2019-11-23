PREFIX?=/usr/local
DYLIB_EXT?=$(shell if [ `uname` == "Darwin" ]; then echo "dylib"; else echo "so"; fi)


all: library

library:
	cargo build --release $(CARGO_FLAGS)

check: library
	cargo test --release $(CARGO_FLAGS)

debug:
	cargo build $(CARGO_FLAGS)
	cargo test $(CARGO_FLAGS)

install: library
	install -d $(PREFIX)/lib/kync_plugins
	install -m 644 target/release/libkync_rawkey.$(DYLIB_EXT) $(PREFIX)/lib/kync_plugins/

.PHONY: uninstall
uninstall:
	rm $(PREFIX)/lib/kync_plugins/libkync_rawkey.$(DYLIB_EXT)

.PHONY: clean
clean:
	cargo clean