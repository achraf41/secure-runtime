#!/bin/bash

echo "=== Cgroup PID test ==="
echo "Main PID: $$"
echo "Main PPID: $PPID"

for i in $(seq 1 30); do
    sleep 20 &
    result=$?

    if [ "$result" -eq 0 ]; then
        echo "Started worker $i PID=$!"
    else
        echo "Failed to start worker $i"
    fi
done

echo "Waiting..."
wait

echo "Finished"
