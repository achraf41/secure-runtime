#!/bin/bash

echo "HELLO FROM STDOUT"

echo "HELLO FROM STDERR" >&2

sleep 1

echo "FINAL STDOUT"

echo "FINAL STDERR" >&2
