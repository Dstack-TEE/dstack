#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
NC='\033[0m' # No Color
RED='\033[0;31m'

TEST_PROC_ID="test-process-0"
UDS="./test.sock"
PIDFILE="./test.pid"

info() {
    printf "${GREEN}$1${NC}\n"
}

error() {
    printf "${RED}$1${NC}\n"
}

assert_eq() {
    local actual="$1"
    local expected="$2"
    local message="$3"
    local assert_ok=n
    if diff <(echo "$actual") <(echo "$expected") >/dev/null; then
        assert_ok=y
    fi
    if [ $assert_ok == "n" ]; then
        error "Assertion failed: $message"
        error "Expected : $expected"
        error "Got      : $actual"
        exit 1
    fi
}

CLI="cargo run -q -p supervisor-client --features cli -- --base-url unix:$UDS"

info "Testing Supervisor CLI commands..."

info "Starting supervisor"
if [ -f $PIDFILE ]; then
    kill $(cat $PIDFILE) 2>/dev/null
fi
rm -f $UDS
cargo run -q --bin supervisor -- --uds $UDS --pid-file $PIDFILE -d

info "Listing processes"
RES=$(${CLI} list | jq .)
assert_eq "$RES" "[]" "List should return empty array"

info "Cleaning up previous test processes"
${CLI} clear >/dev/null 2>&1

# Test list command
info "Testing List command"
RES=$(${CLI} list)
assert_eq "$RES" "[]" "List should return empty array"

# Deploy a new process
info "Testing Deploy command"
RES=$(${CLI} deploy --id ${TEST_PROC_ID} --command sleep --arg 1000)
assert_eq "$RES" null "Deploy should return empty object"

# Get info for specific process
info "Testing Info command"
RES=$(${CLI} info ${TEST_PROC_ID})
assert_eq "$(echo "$RES" | jq -r .config.id)" "${TEST_PROC_ID}" "Info should return object with id"
assert_eq "$(echo "$RES" | jq -r .config.command)" "sleep" "Info should return correct command"
assert_eq "$(echo "$RES" | jq -r .config.args[0])" "1000" "Info should return correct args"
assert_eq "$(echo "$RES" | jq -r .state.status)" "running" "Info should show running status"
assert_eq "$(echo "$RES" | jq -r .state.started)" "true" "Info should show started as true"

# Start the process (should fail as it's already running)
info "Testing Start command"
${CLI} start ${TEST_PROC_ID} 2>/dev/null
assert_eq "$?" 1 "Start should return error"

# Stop the process
info "Testing Stop command"
RES=$(${CLI} stop ${TEST_PROC_ID})
assert_eq "$RES" "null" "Stop should return empty object"

# Get info again to see the stopped state
info "Testing Info command after stop"
RES=$(${CLI} info ${TEST_PROC_ID})
assert_eq "$(echo "$RES" | jq -r .state.status)" "stopped" "Info should show stopped status"
assert_eq "$(echo "$RES" | jq -r .state.started)" "false" "Info should show started as false"

# Can be started again
info "Testing Start command after stop"
RES=$(${CLI} start ${TEST_PROC_ID})
assert_eq "$RES" "null" "Start should return empty object"

# Can not be removed when running
info "Testing Remove command when running"
${CLI} remove ${TEST_PROC_ID} 2>/dev/null
assert_eq "$?" 1 "Remove should return error"

# Stop the process
info "Testing Stop command"
RES=$(${CLI} stop ${TEST_PROC_ID})
assert_eq "$RES" "null" "Stop should return empty object"

# Remove the process
info "Testing Remove command"
RES=$(${CLI} remove ${TEST_PROC_ID})
assert_eq "$RES" "null" "Remove should return empty object"

# Can not start a removed process
info "Testing Start command after remove"
${CLI} start ${TEST_PROC_ID} 2>/dev/null
assert_eq "$?" 1 "Start should return error"

# Test list command
info "Testing List command"
RES=$(${CLI} list)
assert_eq "$RES" "[]" "List should return empty array"

# Test ping command
info "Testing Ping command"
RES=$(${CLI} ping)
assert_eq "$RES" '"pong"' "Ping should return pong"

info "Shutting down supervisor"
${CLI} shutdown 2>/dev/null
kill $(cat $PIDFILE) 2>/dev/null
rm -f $UDS $PIDFILE

info "CLI testing completed!" 
