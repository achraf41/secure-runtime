#!/bin/bash

echo "=== FD inheritance test ==="

for fd in /proc/self/fd/*; do
    echo "$fd -> $(readlink "$fd")"
done
