#!/bin/sh -eu
export RUST_BACKTRACE=1
cargo test           -- --nocapture
cargo test --release -- --nocapture --ignored
