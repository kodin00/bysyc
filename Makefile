# bysyc — build & package shortcuts for the desktop client (bysyc-client).
#
# Intended for a macOS/arm64 host; Windows and Linux are cross-compiled from
# here. Note: Linux builds of cpal need ALSA headers (libasound2-dev) — that
# only matters when building ON Linux; cross/cargo-zigbuild handle it for us
# when building FROM macOS.

.DEFAULT_GOAL := help

# --- Workspace version, read from [workspace.package] in the root Cargo.toml ---
VERSION := $(shell awk '/^\[workspace\.package\]/{sec=1;next} /^\[/{sec=0} sec && $$1=="version"{gsub(/[" ]/,"",$$3); print $$3; exit}' Cargo.toml)

# --- Target triples ---
MACOS_TARGET   := aarch64-apple-darwin
WINDOWS_TARGET := x86_64-pc-windows-gnu
LINUX_TARGET   := x86_64-unknown-linux-gnu

# --- Artifacts written to dist/ ---
MACOS_TARBALL := dist/bysyc-$(VERSION)-$(MACOS_TARGET).tar.gz
# Built with the -gnu toolchain; the zip keeps the canonical -msvc triple.
WINDOWS_ZIP   := dist/bysyc-$(VERSION)-x86_64-pc-windows-msvc.zip
LINUX_TARBALL := dist/bysyc-$(VERSION)-$(LINUX_TARGET).tar.gz

.PHONY: help all macos windows linux clean

# --- Shortcuts ---
help:
	@echo "bysyc client build shortcuts (workspace version $(VERSION))"
	@echo "  make macos    build + package macOS aarch64   -> $(MACOS_TARBALL)"
	@echo "  make windows  build + package Windows x86_64  -> $(WINDOWS_ZIP)"
	@echo "  make linux    build + package Linux x86_64    -> $(LINUX_TARBALL)"
	@echo "  make all      macos + windows + linux"
	@echo "  make clean    remove dist/"

all: macos windows linux

# --- macOS: native build for the host triple ---
macos:
	cargo build --release -p bysyc-client --target $(MACOS_TARGET)
	mkdir -p dist
	tar -czf $(MACOS_TARBALL) -C target/$(MACOS_TARGET)/release bysyc-client

# --- Windows: cross-compile from macOS with the gnu toolchain ---
# One-time setup: brew install mingw-w64 && rustup target add x86_64-pc-windows-gnu
windows:
	cargo build --release -p bysyc-client --target $(WINDOWS_TARGET)
	mkdir -p dist
	zip -qj $(WINDOWS_ZIP) target/$(WINDOWS_TARGET)/release/bysyc-client.exe

# --- Linux: prefer `cross`, fall back to `cargo zigbuild`, else plain cargo ---
# Plain cargo can only link a glibc binary if a Linux toolchain is available.
linux:
	@if command -v cross >/dev/null 2>&1; then \
		cross build --release -p bysyc-client --target $(LINUX_TARGET); \
	elif command -v cargo-zigbuild >/dev/null 2>&1; then \
		cargo zigbuild --release -p bysyc-client --target $(LINUX_TARGET); \
	else \
		cargo build --release -p bysyc-client --target $(LINUX_TARGET); \
	fi
	mkdir -p dist
	tar -czf $(LINUX_TARBALL) -C target/$(LINUX_TARGET)/release bysyc-client

# --- Remove exported artifacts ---
clean:
	rm -rf dist
