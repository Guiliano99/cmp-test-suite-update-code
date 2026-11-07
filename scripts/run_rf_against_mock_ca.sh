#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
#
# Run each Robot Framework suite against its own fresh mock CA, the same way locally and in CI.
# Results go to reports/<suite>/, the mock CA log to reports/<suite>/mock_ca.log.
# Failed tests tagged known-issue are reported as skipped and do not fail the run.
set -euo pipefail

PORT=5000
START_TIMEOUT=180
STOP_TIMEOUT=30

ca_pid=""
failed=""

# ss and curl are not in the CI image, the bash built-in is.
port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; }

start_ca() {
    local log="$1"
    # A leftover listener would satisfy the wait below, and the suite would run against the wrong CA.
    if port_open; then
        echo "Port $PORT is already in use, cannot start a fresh mock CA." >&2
        return 1
    fi
    # setsid makes the CA a group leader, so stop_ca also reaches the child of the Flask reloader.
    setsid python ./mock_ca/ca_handler.py > "$log" 2>&1 &
    ca_pid=$!
    for _ in $(seq 1 "$START_TIMEOUT"); do
        port_open && return 0
        if ! kill -0 "$ca_pid" 2>/dev/null; then
            echo "The mock CA exited during startup, see $log:" >&2
            tail -n 50 "$log" >&2
            return 1
        fi
        sleep 1
    done
    echo "The mock CA did not listen on port $PORT within ${START_TIMEOUT}s, see $log." >&2
    return 1
}

stop_ca() {
    [ -n "$ca_pid" ] || return 0
    kill -TERM -- "-$ca_pid" 2>/dev/null || true
    sleep 2
    kill -KILL -- "-$ca_pid" 2>/dev/null || true
    wait "$ca_pid" 2>/dev/null || true
    ca_pid=""
    for _ in $(seq 1 "$STOP_TIMEOUT"); do
        port_open || return 0
        sleep 1
    done
}

trap stop_ca EXIT
# Robot Framework exits normally on Ctrl-C, so without this the next suite would start.
trap 'exit 130' INT

cd "$(dirname "${BASH_SOURCE[0]}")/.."

for suite in tests tests_pq_and_hybrid tests_mock_ca; do
    mkdir -p "reports/$suite"
    # Trust anchor written during a test run; each suite starts without it, as on a fresh checkout.
    rm -f data/trustanchors/issued_cert_root.pem
    start_ca "reports/$suite/mock_ca.log" || exit 1
    robot --pythonpath=./ --exclude verbose-tests --skiponfailure known-issue --outputdir "reports/$suite" \
        --variable environment:mock_ca "$suite" || failed="$failed $suite"
    stop_ca
done

if [ -n "$failed" ]; then
    echo "Failed suites:$failed" >&2
    exit 1
fi
