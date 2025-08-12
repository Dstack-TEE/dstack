#!/bin/bash
set -e

(cd sdk/simulator && ./build.sh)

pushd sdk/simulator
./dstack-simulator &
SIMULATOR_PID=$!
trap "kill $SIMULATOR_PID 2>/dev/null || true" EXIT
echo "Simulator process (PID: $SIMULATOR_PID) started."
popd

export DSTACK_SIMULATOR_ENDPOINT=$(realpath sdk/simulator/dstack.sock)
export TAPPD_SIMULATOR_ENDPOINT=$(realpath sdk/simulator/tappd.sock)

echo "DSTACK_SIMULATOR_ENDPOINT: $DSTACK_SIMULATOR_ENDPOINT"
echo "TAPPD_SIMULATOR_ENDPOINT: $TAPPD_SIMULATOR_ENDPOINT"

# Run the tests
cargo test --all-features -- --show-output
