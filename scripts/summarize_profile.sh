#!/usr/bin/env bash

set -u

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <report-directory>"
    exit 1
fi

REPORT_DIR="$1"

if [ ! -d "$REPORT_DIR" ]; then
    echo "Report directory does not exist: $REPORT_DIR"
    exit 1
fi

echo "=================================================="
echo "EXECUTED FILES"
echo "=================================================="

grep -hE \
    'execve\(' \
    "$REPORT_DIR"/strace* 2>/dev/null \
    | sed -n 's/.*execve("\([^"]*\)".*/\1/p' \
    | sort -u

echo
echo "=================================================="
echo "OPENED FILE PATHS"
echo "=================================================="

grep -hE \
    'openat\(|open\(|stat\(|newfstatat\(|access\(' \
    "$REPORT_DIR"/strace* 2>/dev/null \
    | grep -oE '"(/[^"]+)"' \
    | tr -d '"' \
    | sort -u

echo
echo "=================================================="
echo "NETWORK CONNECT/BIND CALLS"
echo "=================================================="

grep -hE \
    'connect\(|bind\(|listen\(' \
    "$REPORT_DIR"/strace* 2>/dev/null \
    | sort -u

echo
echo "=================================================="
echo "PROCESS CREATION"
echo "=================================================="

grep -hE \
    'clone\(|clone3\(|fork\(|vfork\(|execve\(' \
    "$REPORT_DIR"/strace* 2>/dev/null \
    | sort -u

echo
echo "=================================================="
echo "DENIED OPERATIONS"
echo "=================================================="

grep -hE \
    'EACCES|EPERM' \
    "$REPORT_DIR"/strace* 2>/dev/null \
    | sort -u
