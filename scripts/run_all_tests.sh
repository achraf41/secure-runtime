#!/bin/bash

# ==========================================================
# Secure Runtime - V2 Test Runner
# ==========================================================

GREEN="\033[0;32m"
RED="\033[0;31m"
BLUE="\033[0;34m"
NC="\033[0m"

PASS_COUNT=0
FAIL_COUNT=0

run_test() {
    local NAME="$1"
    local POLICY="$2"
    local APP="$3"
    local EXPECTED="$4"

    echo -e "${BLUE}========================================================${NC}"
    echo -e "${BLUE}Running: $NAME${NC}"
    echo -e "${BLUE}========================================================${NC}"

    OUTPUT=$(cargo run --quiet -- --policy "$POLICY" --app "$APP" 2>&1)

    echo "$OUTPUT"
    echo

    if echo "$OUTPUT" | grep -q "$EXPECTED"; then
        echo -e "${GREEN}PASS - $NAME${NC}"
        ((PASS_COUNT++))
    else
        echo -e "${RED}FAIL - $NAME${NC}"
        ((FAIL_COUNT++))
    fi

    echo
}

# ==========================================================
# Filesystem
# ==========================================================

run_test \
"Filesystem Sandbox" \
"policies/fs_probe.json" \
"./bin/fs_test" \
"OK: forbidden read was blocked"

# ==========================================================
# Memory Limit
# ==========================================================

run_test \
"Memory Limit" \
"policies/memory_limit_probe.json" \
"./bin/memory_limit_test" \
"memory allocation failed"

# ==========================================================
# CPU Limit
# ==========================================================

run_test \
"CPU Limit" \
"policies/cpu_limit_probe.json" \
"./bin/cpu_limit_test" \
"SIGKILL"

# ==========================================================
# File Size Limit
# ==========================================================

run_test \
"File Size Limit" \
"policies/file_limit_probe.json" \
"./bin/file_limit_test" \
"File size limit exceeded"

# ==========================================================
# Process Limit
# ==========================================================

run_test \
"Process Limit" \
"policies/process_limit_probe.json" \
"./bin/process_limit_test" \
"Resource temporarily unavailable"

# ==========================================================
# Network Connect Deny
# ==========================================================

run_test \
"Network Connect Deny" \
"policies/network_connect_deny.json" \
"./bin/network_connect_test" \
"TCP connection was blocked"

# ==========================================================
# Network Connect Allow
# ==========================================================

run_test \
"Network Connect Allow" \
"policies/network_connect_allow.json" \
"./bin/network_connect_test" \
"TCP connection to port 80 was allowed"

# ==========================================================
# Network Bind Deny
# ==========================================================

run_test \
"Network Bind Deny" \
"policies/network_bind_deny.json" \
"./bin/network_bind_test" \
"Permission denied"

# ==========================================================
# Network Bind Allow
# ==========================================================

run_test \
"Network Bind Allow" \
"policies/network_bind_allow.json" \
"./bin/network_bind_test" \
"TCP bind to 127.0.0.1:8080 was allowed"

# =========================================================
# ================= Seccomp Deny ==========================
# =========================================================

run_test \
"Seccomp ptrace deny" \
"policies/seccomp_ptrace_deny.json" \
"./target/debug/ptrace_test" \
"OK: ptrace was blocked by Seccomp"


# =========================================================
# ================== Seccomp Allow ========================
# =========================================================

run_test \
"Seccomp ptrace allow" \
"policies/seccomp_ptrace_allow.json" \
"./target/debug/ptrace_test" \
"ptrace succeeded"

# ==========================================================
# Summary
# ==========================================================

echo
echo "========================================================"
echo "                 TEST SUMMARY"
echo "========================================================"

echo -e "${GREEN}Passed : $PASS_COUNT${NC}"
echo -e "${RED}Failed : $FAIL_COUNT${NC}"

echo

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "${GREEN}All tests passed successfully!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
