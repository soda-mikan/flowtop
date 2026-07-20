#!/usr/bin/env sh
set -eu

rustup toolchain install stable --component clippy --component rustfmt
rustup toolchain install nightly --component rust-src
cargo install bpf-linker --version 0.10.4 --locked
