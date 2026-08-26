#!/bin/bash

echo "=== Timeout test ==="
echo "PID: $$"
echo "PPID: $PPID"

echo "Starting worker..."
sleep 30 &
WORKER=$!

echo "Worker PID: $WORKER"
echo "Main application will now sleep for 30 seconds"

sleep 30

echo "ERROR: timeout did not work"
wait
