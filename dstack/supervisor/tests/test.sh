#!/bin/bash

# SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Base URL
BASE_URL="http://localhost"
UDS="./test.sock"
PIDFILE="./test.pid"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

PROG_ID_1="test-process-1"
PROG_ID_2="test-process-2"

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

info "Starting supervisor"
if [ -f $PIDFILE ]; then
    kill $(cat $PIDFILE) 2>/dev/null
fi
rm -f $UDS
cargo run -q --bin supervisor -- --uds $UDS --pid-file $PIDFILE -d

info "Testing Supervisor API endpoints..."

http() {
  curl --unix-socket $UDS -s -X "$1" "$2" -H "Content-Type: application/json" -d "$3"
}

info "Cleaning up previous test processes"
http POST "${BASE_URL}/clear" >/dev/null 2>&1

info "Listing processes"
RES=$(http GET "${BASE_URL}/list")
assert_eq "$RES" '{"data":[]}' "List should return empty array"

# Deploy a new process
info "Testing Deploy endpoint"
RES=$(http POST "${BASE_URL}/deploy" '{
  "id": "'"$PROG_ID_1"'",
  "command": "sleep",
  "args": ["1000"],
  "cwd": "/tmp"
}')
assert_eq "$RES" '{"data":null}' "Deploy should return empty object"

# Get info for specific process
info "Testing Info endpoint"
RES=$(http GET "${BASE_URL}/info/$PROG_ID_1")
assert_eq "$(echo "$RES" | jq -r .data.config.id)" "$PROG_ID_1" "Info should return object with id"
assert_eq "$(echo "$RES" | jq -r .data.config.command)" "sleep" "Info should return correct command"
assert_eq "$(echo "$RES" | jq -r .data.config.args[0])" "1000" "Info should return correct args"
assert_eq "$(echo "$RES" | jq -r .data.config.cwd)" "/tmp" "Info should return correct working directory"
assert_eq "$(echo "$RES" | jq -r .data.state.status)" "running" "Info should show running status"
assert_eq "$(echo "$RES" | jq -r .data.state.started)" "true" "Info should show started as true"

# Start the process
info "Testing Start endpoint"
RES=$(http POST "${BASE_URL}/start/$PROG_ID_1")
assert_eq "$RES" '{"error":"Process is already running"}' "Start should return error"

# Stop the process
info "Testing Stop endpoint"
RES=$(http POST "${BASE_URL}/stop/$PROG_ID_1")
assert_eq "$RES" '{"data":null}' "Stop should return empty object"

# Get info again to see the stopped state
info "Testing Info endpoint after stop"
RES=$(http GET "${BASE_URL}/info/$PROG_ID_1")
assert_eq "$(echo "$RES" | jq -r .data.config.id)" "$PROG_ID_1" "Info should return object with id"
assert_eq "$(echo "$RES" | jq -r .data.config.command)" "sleep" "Info should return correct command"
assert_eq "$(echo "$RES" | jq -r .data.config.args[0])" "1000" "Info should return correct args"
assert_eq "$(echo "$RES" | jq -r .data.config.cwd)" "/tmp" "Info should return correct working directory"
assert_eq "$(echo "$RES" | jq -r .data.state.status)" "stopped" "Info should show stopped status"
assert_eq "$(echo "$RES" | jq -r .data.state.started)" "false" "Info should show started as false"

# Test list command after adding process
info "Testing List command with process"
RES=$(http GET "${BASE_URL}/list")
assert_eq "$(echo "$RES" | jq '.data | length')" "1" "List should show one process"

# Remove the process
info "Testing Remove process"
RES=$(http DELETE "${BASE_URL}/remove/$PROG_ID_1")
assert_eq "$RES" '{"data":null}' "Remove should return empty object"

# Can not start a removed process
info "Testing Start endpoint after remove"
RES=$(http POST "${BASE_URL}/start/$PROG_ID_1")
assert_eq "$RES" '{"error":"Process not found"}' "Start should return error"


# Test deploying with all optional parameters
info "Testing Deploy with all parameters"
rm -rf /tmp/stdout.log /tmp/stderr.log /tmp/test.pid /tmp/stdout.log.1
RES=$(http POST "${BASE_URL}/deploy" '
{
    "id": "'"$PROG_ID_2"'",
    "name": "test-name",
    "command": "bash",
    "args": ["-c", "echo hello world, FOO=$FOO, pwd=$(pwd); echo hello stderr >&2; sleep 2; echo after rotation;"],
    "env": {
        "FOO": "bar",
        "BAZ": "qux"
    },
    "cwd": "/var/tmp",
    "stdout": "/tmp/stdout.log",
    "stderr": "/tmp/stderr.log", 
    "pidfile": "/tmp/test.pid"
}')
assert_eq "$RES" '{"data":null}' "Deploy should return empty object"

# Verify all parameters were set correctly
info "Testing Info endpoint for process with all parameters"
RES=$(http GET "${BASE_URL}/info/$PROG_ID_2")
assert_eq "$(echo "$RES" | jq -r .data.config.id)" "$PROG_ID_2" "Info should return correct id"
assert_eq "$(echo "$RES" | jq -r .data.config.name)" "test-name" "Info should return correct name"
assert_eq "$(echo "$RES" | jq -r .data.config.command)" "bash" "Info should return correct command"
assert_eq "$(echo "$RES" | jq -r .data.config.env.FOO)" "bar" "Info should return correct env var FOO"
assert_eq "$(echo "$RES" | jq -r .data.config.env.BAZ)" "qux" "Info should return correct env var BAZ"
assert_eq "$(echo "$RES" | jq -r .data.config.cwd)" "/var/tmp" "Info should return correct working directory"
assert_eq "$(echo "$RES" | jq -r .data.config.stdout)" "/tmp/stdout.log" "Info should return correct stdout path"
assert_eq "$(echo "$RES" | jq -r .data.config.stderr)" "/tmp/stderr.log" "Info should return correct stderr path"
assert_eq "$(echo "$RES" | jq -r .data.config.pidfile)" "/tmp/test.pid" "Info should return correct pidfile path"
sleep 1

# Check stdout file exists and contains expected output
info "Testing stdout file contents"
assert_eq "$(cat "/tmp/stdout.log")" "hello world, FOO=bar, pwd=/var/tmp"  

# Check stderr file exists and contains expected output
info "Testing stderr file contents" 
assert_eq "$(cat "/tmp/stderr.log")" "hello stderr" "Stderr file should contain expected output"

# Check pid file exists and contains expected pid
info "Testing pid file contents"
PID=$(echo "$RES" | jq -r .data.state.pid)
if [ -f "/tmp/test.pid" ]; then
    PIDFILE_CONTENTS=$(cat "/tmp/test.pid")
    assert_eq "$PIDFILE_CONTENTS" "$PID" "Pidfile should contain correct pid"
else
    error "Pidfile does not exist"
    exit 1
fi
mv "/tmp/stdout.log" "/tmp/stdout.log.1"
sleep 2
# Check stdout file contents after rotation
info "Testing stdout file contents after rotation"
assert_eq "$(cat "/tmp/stdout.log")" "after rotation" "Stdout file should contain expected output"

# Clean up
info "Cleaning up test process $PROG_ID_2"
RES=$(http POST "${BASE_URL}/stop/$PROG_ID_2")
assert_eq "$RES" '{"data":null}' "Stop should return empty object"
RES=$(http DELETE "${BASE_URL}/remove/$PROG_ID_2")
assert_eq "$RES" '{"data":null}' "Remove should return empty object"

# Test list command
info "Testing List command"
RES=$(http GET "${BASE_URL}/list")
assert_eq "$RES" '{"data":[]}' "List should return empty array"


# Test ping endpoint
info "Testing Ping endpoint"
RES=$(http GET "${BASE_URL}/ping")
assert_eq "$RES" '{"data":"pong"}' "Ping should return pong"

# Test clear endpoint
info "Testing Clear endpoint"
RES=$(http POST "${BASE_URL}/clear")
assert_eq "$RES" '{"data":null}' "Clear should return empty object"

# Verify list is empty after clear
RES=$(http GET "${BASE_URL}/list")
assert_eq "$RES" '{"data":[]}' "List should be empty after clear"

info "Shutting down supervisor"
http POST "${BASE_URL}/shutdown"
kill $(cat $PIDFILE) 2>/dev/null
rm -f $UDS $PIDFILE

info "API testing completed!"
