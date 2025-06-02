#!/bin/bash
cd $(dirname $0)
cargo build --release -p dstack-guest-agent
cp ../../target/release/dstack-guest-agent .
ln -sf dstack-guest-agent dstack-simulator

