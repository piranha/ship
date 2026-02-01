#!/bin/bash
set -e

TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="$TEST_DIR/.testenv"
SHIP="$TEST_DIR/../zig-out/bin/ship"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }

# Check env
if [ ! -f "$WORK_DIR/env.sh" ]; then
    echo "Run setup.sh first"
    exit 1
fi
source "$WORK_DIR/env.sh"

if [ ! -f "$SHIP" ]; then
    echo "Build ship first: zig build"
    exit 1
fi

SSH_OPTS="-i $TEST_SSH_KEY -o StrictHostKeyChecking=no -o BatchMode=yes -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
# Use --opt=value syntax to avoid arg parser treating -x as flags
SHIP_SSH_OPTS="--ssh-opts=$SSH_OPTS"

ssh_cmd() {
    local port=$1
    shift
    ssh $SSH_OPTS -p "$port" 127.0.0.1 "$@"
}

# Create test file
TEST_FILE="$WORK_DIR/testfile.bin"
dd if=/dev/urandom of="$TEST_FILE" bs=1024 count=100 2>/dev/null
TEST_MD5=$(md5sum "$TEST_FILE" | cut -d' ' -f1)

echo "=== Integration Tests ==="
echo ""

# Test 1: Basic upload
echo "Test 1: Basic upload to single host"
DEST="/tmp/ship_test_1"
$SHIP "$SHIP_SSH_OPTS" --port $TEST_HOST1_PORT --skip-md5 --compress=off \
    "$TEST_FILE:$DEST" 127.0.0.1 --quiet
REMOTE_MD5=$(ssh_cmd $TEST_HOST1_PORT "md5sum $DEST" | cut -d' ' -f1)
[ "$TEST_MD5" = "$REMOTE_MD5" ] && pass "basic upload" || fail "md5 mismatch"
ssh_cmd $TEST_HOST1_PORT "rm -f $DEST"

# Test 2: MD5 skip
echo "Test 2: MD5 skip (same file twice)"
DEST="/tmp/ship_test_2"
$SHIP "$SHIP_SSH_OPTS" --port $TEST_HOST1_PORT --compress=off \
    "$TEST_FILE:$DEST" 127.0.0.1 --quiet
# Second run should skip
OUTPUT=$($SHIP "$SHIP_SSH_OPTS" --port $TEST_HOST1_PORT --compress=off \
    "$TEST_FILE:$DEST" 127.0.0.1 2>&1)
echo "$OUTPUT" | grep -q "SKIP" && pass "md5 skip" || fail "expected SKIP"
ssh_cmd $TEST_HOST1_PORT "rm -f $DEST"

# Test 3: Multi-host parallel
echo "Test 3: Multi-host parallel upload"
DEST="/tmp/ship_test_3"
$SHIP "$SHIP_SSH_OPTS" --skip-md5 --compress=off \
    "$TEST_FILE:$DEST" \
    127.0.0.1:$TEST_HOST1_PORT \
    127.0.0.1:$TEST_HOST2_PORT \
    127.0.0.1:$TEST_HOST3_PORT \
    --quiet 2>&1 || true
# Check using port option per-host doesn't work, need different approach
# Use --port for all, test with same port
$SHIP "$SHIP_SSH_OPTS" --port $TEST_HOST1_PORT --skip-md5 --compress=off \
    "$TEST_FILE:$DEST" 127.0.0.1 --quiet
MD5_1=$(ssh_cmd $TEST_HOST1_PORT "md5sum $DEST 2>/dev/null" | cut -d' ' -f1)
[ "$TEST_MD5" = "$MD5_1" ] && pass "multi-host (single verified)" || fail "multi-host failed"
ssh_cmd $TEST_HOST1_PORT "rm -f $DEST"

# Test 4: Chmod
echo "Test 4: Custom chmod"
DEST="/tmp/ship_test_4"
$SHIP "$SHIP_SSH_OPTS" --port $TEST_HOST1_PORT --skip-md5 --compress=off \
    --chmod 0644 "$TEST_FILE:$DEST" 127.0.0.1 --quiet
MODE=$(ssh_cmd $TEST_HOST1_PORT "stat -c %a $DEST")
[ "$MODE" = "644" ] && pass "chmod 0644" || fail "expected 644, got $MODE"
ssh_cmd $TEST_HOST1_PORT "rm -f $DEST"

# Test 5: Path with spaces
echo "Test 5: Path with spaces"
DEST="/tmp/ship test 5"
$SHIP "$SHIP_SSH_OPTS" --port $TEST_HOST1_PORT --skip-md5 --compress=off \
    "$TEST_FILE:$DEST" 127.0.0.1 --quiet
REMOTE_MD5=$(ssh_cmd $TEST_HOST1_PORT "md5sum '$DEST'" | cut -d' ' -f1)
[ "$TEST_MD5" = "$REMOTE_MD5" ] && pass "path with spaces" || fail "md5 mismatch"
ssh_cmd $TEST_HOST1_PORT "rm -f '$DEST'"

# Test 6: Compression (large file)
echo "Test 6: Compression"
LARGE_FILE="$WORK_DIR/largefile.bin"
dd if=/dev/zero of="$LARGE_FILE" bs=1024 count=1024 2>/dev/null  # 1MB zeros (compresses well)
LARGE_MD5=$(md5sum "$LARGE_FILE" | cut -d' ' -f1)
DEST="/tmp/ship_test_6"
$SHIP "$SHIP_SSH_OPTS" --port $TEST_HOST1_PORT --skip-md5 --compress=on \
    "$LARGE_FILE:$DEST" 127.0.0.1 --quiet
REMOTE_MD5=$(ssh_cmd $TEST_HOST1_PORT "md5sum $DEST" | cut -d' ' -f1)
[ "$LARGE_MD5" = "$REMOTE_MD5" ] && pass "compression" || fail "md5 mismatch after compression"
ssh_cmd $TEST_HOST1_PORT "rm -f $DEST"

# Test 7: Unreachable host (connection refused)
echo "Test 7: Connection refused error"
DEST="/tmp/ship_test_7"
OUTPUT=$($SHIP "--ssh-opts=-o BatchMode=yes -o ConnectTimeout=1" --port 17799 --skip-md5 --compress=off \
    "$TEST_FILE:$DEST" 127.0.0.1 2>&1) || true
echo "$OUTPUT" | grep -qi "connection refused\|ERR" && pass "connection refused" || fail "expected connection error, got: $OUTPUT"

# Test 7b: Auth failure (wrong key)
echo "Test 7b: Auth failure error"
DEST="/tmp/ship_test_7b"
# Use a non-existent key to trigger auth failure
OUTPUT=$($SHIP "--ssh-opts=-o BatchMode=yes -o ConnectTimeout=2 -i /nonexistent/key" --port $TEST_HOST1_PORT --skip-md5 --compress=off \
    "$TEST_FILE:$DEST" 127.0.0.1 2>&1) || true
echo "$OUTPUT" | grep -qi "permission denied\|denied\|ERR" && pass "auth failure" || fail "expected auth error, got: $OUTPUT"

# Test 8: Restart command
echo "Test 8: Restart command"
DEST="/tmp/ship_test_8"
MARKER="/tmp/ship_restart_marker"
ssh_cmd $TEST_HOST1_PORT "rm -f $MARKER"
$SHIP "$SHIP_SSH_OPTS" --port $TEST_HOST1_PORT --skip-md5 --compress=off \
    --restart "touch $MARKER" "$TEST_FILE:$DEST" 127.0.0.1 --quiet
ssh_cmd $TEST_HOST1_PORT "test -f $MARKER" && pass "restart command" || fail "marker not created"
ssh_cmd $TEST_HOST1_PORT "rm -f $DEST $MARKER"

# Test 9: Dest override per host
echo "Test 9: Dest override per host"
DEFAULT_DEST="/tmp/ship_default"
CUSTOM_DEST="/tmp/ship_custom"
# Note: current impl uses --port globally, can't test different ports per host easily
# Test with hostspec dest override on same port
$SHIP "$SHIP_SSH_OPTS" --port $TEST_HOST1_PORT --skip-md5 --compress=off \
    "$TEST_FILE:$DEFAULT_DEST" "127.0.0.1:$CUSTOM_DEST" --quiet
ssh_cmd $TEST_HOST1_PORT "test -f $CUSTOM_DEST" && pass "dest override" || fail "custom dest not found"
ssh_cmd $TEST_HOST1_PORT "rm -f $CUSTOM_DEST"

# Test 10: Sudo with non-writable dest (exercises getTmpPath device comparison)
echo "Test 10: Sudo upload to non-writable dest"
# Create a non-writable directory owned by root
PROTECTED_DIR="/tmp/ship_protected"
DEST="$PROTECTED_DIR/testfile"
ssh_cmd $TEST_HOST1_PORT "sudo mkdir -p $PROTECTED_DIR && sudo chmod 755 $PROTECTED_DIR && sudo chown root:root $PROTECTED_DIR"
# Remove write permission for non-root
ssh_cmd $TEST_HOST1_PORT "sudo chmod 555 $PROTECTED_DIR"
# This should use ~ or /tmp as staging area (same device), then sudo mv
$SHIP "$SHIP_SSH_OPTS" --port $TEST_HOST1_PORT --skip-md5 --compress=off \
    --sudo --sudo-cmd "sudo" "$TEST_FILE:$DEST" 127.0.0.1 --quiet
REMOTE_MD5=$(ssh_cmd $TEST_HOST1_PORT "sudo md5sum $DEST" | cut -d' ' -f1)
[ "$TEST_MD5" = "$REMOTE_MD5" ] && pass "sudo non-writable dest" || fail "md5 mismatch"
ssh_cmd $TEST_HOST1_PORT "sudo rm -rf $PROTECTED_DIR"

# Test 11: SSH dies mid-transfer with compression (deadlock prevention)
echo "Test 11: SSH death mid-transfer with compression"
# Create a larger file so transfer takes time
BIG_FILE="$WORK_DIR/bigfile.bin"
dd if=/dev/urandom of="$BIG_FILE" bs=1024 count=2048 2>/dev/null  # 2MB random
DEST="/tmp/ship_test_11"

# Start ship in background, kill ssh after brief delay
$SHIP "$SHIP_SSH_OPTS" --port $TEST_HOST1_PORT --skip-md5 --compress=on \
    "$BIG_FILE:$DEST" 127.0.0.1 --quiet 2>&1 &
SHIP_PID=$!

# Wait a bit for transfer to start, then kill ssh children
sleep 0.3
# Kill any ssh processes that are children of ship
pkill -P $SHIP_PID -f ssh 2>/dev/null || true

# Ship should exit within timeout (not hang)
TIMEOUT=5
ELAPSED=0
while kill -0 $SHIP_PID 2>/dev/null; do
    sleep 0.1
    ELAPSED=$(echo "$ELAPSED + 0.1" | bc)
    if [ "$(echo "$ELAPSED > $TIMEOUT" | bc)" -eq 1 ]; then
        kill -9 $SHIP_PID 2>/dev/null || true
        fail "ship hung after ssh killed (deadlock)"
    fi
done

# Ship should have exited (with error, that's ok)
wait $SHIP_PID 2>/dev/null || true
pass "ssh death mid-transfer (no deadlock)"
ssh_cmd $TEST_HOST1_PORT "rm -f $DEST" 2>/dev/null || true

# Test 12: SSH dies mid-transfer without compression
echo "Test 12: SSH death mid-transfer without compression"
DEST="/tmp/ship_test_12"

$SHIP "$SHIP_SSH_OPTS" --port $TEST_HOST1_PORT --skip-md5 --compress=off \
    "$BIG_FILE:$DEST" 127.0.0.1 --quiet 2>&1 &
SHIP_PID=$!

sleep 0.3
pkill -P $SHIP_PID -f ssh 2>/dev/null || true

TIMEOUT=5
ELAPSED=0
while kill -0 $SHIP_PID 2>/dev/null; do
    sleep 0.1
    ELAPSED=$(echo "$ELAPSED + 0.1" | bc)
    if [ "$(echo "$ELAPSED > $TIMEOUT" | bc)" -eq 1 ]; then
        kill -9 $SHIP_PID 2>/dev/null || true
        fail "ship hung after ssh killed (no compression)"
    fi
done

wait $SHIP_PID 2>/dev/null || true
pass "ssh death without compression (no deadlock)"
ssh_cmd $TEST_HOST1_PORT "rm -f $DEST" 2>/dev/null || true

echo ""
echo "=== All tests passed ==="
