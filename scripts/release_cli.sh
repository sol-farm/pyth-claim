#! /bin/bash

# build the krylon-cli first
RUSTFLAGS="-C target-cpu=native" cargo build --release && cp target/release/cli rust-starter
