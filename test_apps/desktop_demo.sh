#!/bin/bash

NAME="${1:-User}"
COUNT="${2:-4}"

if ! [[ "$COUNT" =~ ^[1-9][0-9]*$ ]] || (( COUNT > 10 )); then
    echo "Error: count must be a number between 1 and 10." >&2
    exit 2
fi

echo "========================================"
echo "       SECURE RUNTIME DEMO"
echo "========================================"
echo
echo "Hello, $NAME!"
echo "Iterations requested: $COUNT"
echo "Process PID: $$"
echo

echo "[diagnostic] stderr capture is working" >&2

for ((i=1; i<=COUNT; i++)); do
    echo "[$i/$COUNT] Application running inside Secure Runtime..."
    /usr/bin/sleep 0.4
done

echo
echo "Demo completed successfully."
exit 0
