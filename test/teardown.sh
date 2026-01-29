#!/bin/bash

TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="$TEST_DIR/.testenv"

PORTS=(17722 17723 17724)

for port in "${PORTS[@]}"; do
    pkill -f "sshd.*-p $port" 2>/dev/null || true
done

rm -rf "$WORK_DIR"

echo "Test environment cleaned up."
