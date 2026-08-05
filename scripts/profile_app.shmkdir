#!/usr/bin/env bash

set -u

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <report-name> <command> [arguments...]"
    exit 1
fi

REPORT_NAME="$1"
shift

REPORT_DIR="reports/$REPORT_NAME"
TRACE_FILE="$REPORT_DIR/strace"
PROCESS_FILE="$REPORT_DIR/processes.txt"
SOCKET_FILE="$REPORT_DIR/sockets.txt"
RESOURCE_FILE="$REPORT_DIR/resources.txt"
COMMAND_FILE="$REPORT_DIR/command.txt"

mkdir -p "$REPORT_DIR"

printf '%q ' "$@" > "$COMMAND_FILE"
printf '\n' >> "$COMMAND_FILE"

echo "Starting application profiling..."
echo "Report directory: $REPORT_DIR"

strace \
    -ff \
    -tt \
    -yy \
    -s 256 \
    -e trace=%file,%network,%process,%ipc \
    -o "$TRACE_FILE" \
    "$@" &

TRACED_PID=$!

echo "Profiler PID: $TRACED_PID"

while kill -0 "$TRACED_PID" 2>/dev/null; do
    {
        echo "===== $(date --iso-8601=seconds) ====="
        ps -eo pid,ppid,user,%cpu,%mem,rss,vsz,stat,cmd --forest
    } >> "$PROCESS_FILE"

    {
        echo "===== $(date --iso-8601=seconds) ====="
        ss -lntup
        ss -ntup
    } >> "$SOCKET_FILE" 2>&1

    {
        echo "===== $(date --iso-8601=seconds) ====="

        if [ -r "/proc/$TRACED_PID/status" ]; then
            grep -E \
                '^(Name|Pid|PPid|Threads|VmPeak|VmSize|VmRSS|VmHWM):' \
                "/proc/$TRACED_PID/status"
        fi
    } >> "$RESOURCE_FILE"

    sleep 2
done

wait "$TRACED_PID"
EXIT_CODE=$?

echo "Application exited with code: $EXIT_CODE"
echo "Profiling finished."
echo "Results saved in: $REPORT_DIR"

exit "$EXIT_CODE"
