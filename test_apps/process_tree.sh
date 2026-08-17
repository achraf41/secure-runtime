#!/bin/bash

echo "=== PID supervisor test ==="
echo "Main PID: $$"
echo "Main PPID: $PPID"

sleep 30 &
WORKER=$!

echo "Worker PID: $WORKER"

sleep 2

echo "Main application exiting now"
exit 0
