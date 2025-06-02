#!/bin/bash
set -e

(cd sdk/simulator && ./build.sh)

pushd sdk/simulator
./dstack-simulator &
SIMULATOR_PID=$!
echo "Simulator process (PID: $SIMULATOR_PID) started."
popd

export DSTACK_SIMULATOR_ENDPOINT=$(realpath sdk/simulator/dstack.sock)

echo "DSTACK_SIMULATOR_ENDPOINT: $DSTACK_SIMULATOR_ENDPOINT"

# Run the tests
cargo test

# Kill the simulator after tests finish
kill $SIMULATOR_PID
echo "Simulator process (PID: $SIMULATOR_PID) terminated."
