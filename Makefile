.PHONY: help prepare install rust-lint clean build build-release
.DEFAULT_GOAL := help
SHELL:=/bin/bash


# Add help text after each target name starting with '\#\#'
help:   ## show this help
	@echo -e "Help for this makefile\n"
	@echo "Possible commands are:"
	@grep -h "##" $(MAKEFILE_LIST) | grep -v grep | sed -e 's/\(.*\):.*##\(.*\)/    \1: \2/'

prepare:  ## install Rust and Soroban-CLI
	# install Rust
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh && \


install:
	pip install -e ".[dev]"

rust-lint:
	cd rust && cargo clippy --all-targets --all-features -- -Dwarnings
	cd rust && cargo fmt -- --emit files

clean:
	rm rust/target/release/*.wasm
	rm rust/target/release/*.d
	cd rust && cargo clean

# --------- Build --------- #

build:
	maturin develop

build-release:
	maturin develop --release
