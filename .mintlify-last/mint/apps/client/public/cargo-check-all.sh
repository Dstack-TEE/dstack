#!/bin/sh
find . -name Cargo.toml -exec dirname {} \; | while read dir; do
    echo "Checking $dir..."
    (cd "$dir" && cargo check)
done
