#!/bin/bash
set -e

TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="$TEST_DIR/.testenv"

# Ports 17722-17724 (obscure enough)
PORTS=(17722 17723 17724)

cleanup_old() {
    for port in "${PORTS[@]}"; do
        pkill -f "sshd.*-p $port" 2>/dev/null || true
    done
    rm -rf "$WORK_DIR"
}

cleanup_old

mkdir -p "$WORK_DIR"/{keys,configs,roots,pids}

# Generate test keys
ssh-keygen -t ed25519 -f "$WORK_DIR/keys/test_key" -N "" -q
ssh-keygen -t ed25519 -f "$WORK_DIR/keys/host_key" -N "" -q

# Create authorized_keys
mkdir -p "$WORK_DIR/roots/"{host1,host2,host3}/.ssh
for h in host1 host2 host3; do
    cp "$WORK_DIR/keys/test_key.pub" "$WORK_DIR/roots/$h/.ssh/authorized_keys"
    chmod 700 "$WORK_DIR/roots/$h/.ssh"
    chmod 600 "$WORK_DIR/roots/$h/.ssh/authorized_keys"
    mkdir -p "$WORK_DIR/roots/$h/tmp"
    mkdir -p "$WORK_DIR/roots/$h/dest"
done

# Generate sshd configs
for i in 0 1 2; do
    port="${PORTS[$i]}"
    host="host$((i+1))"
    cat > "$WORK_DIR/configs/sshd_$host.conf" << EOF
Port $port
ListenAddress 127.0.0.1
HostKey $WORK_DIR/keys/host_key
PidFile $WORK_DIR/pids/sshd_$host.pid
AuthorizedKeysFile $WORK_DIR/roots/$host/.ssh/authorized_keys
StrictModes no
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM no
Subsystem sftp /usr/lib/ssh/sftp-server
PrintMotd no
AcceptEnv LANG LC_*
EOF
done

# Start sshds
for i in 0 1 2; do
    host="host$((i+1))"
    /usr/sbin/sshd -f "$WORK_DIR/configs/sshd_$host.conf" -E "$WORK_DIR/sshd_$host.log"
    echo "Started sshd for $host on port ${PORTS[$i]}"
done

# Wait for sshds to be ready
sleep 1

# Verify connectivity
for i in 0 1 2; do
    port="${PORTS[$i]}"
    if ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no \
           -i "$WORK_DIR/keys/test_key" -p "$port" 127.0.0.1 "echo ok" >/dev/null 2>&1; then
        echo "  port $port: OK"
    else
        echo "  port $port: FAILED"
        exit 1
    fi
done

# Write env file for tests
cat > "$WORK_DIR/env.sh" << EOF
export TEST_SSH_KEY="$WORK_DIR/keys/test_key"
export TEST_HOST1_PORT=17722
export TEST_HOST2_PORT=17723
export TEST_HOST3_PORT=17724
export TEST_HOST1_ROOT="$WORK_DIR/roots/host1"
export TEST_HOST2_ROOT="$WORK_DIR/roots/host2"
export TEST_HOST3_ROOT="$WORK_DIR/roots/host3"
EOF

echo ""
echo "Test environment ready. Source $WORK_DIR/env.sh"
echo "Run teardown.sh to clean up."
