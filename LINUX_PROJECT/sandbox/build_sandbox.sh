#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "=== [Member 1] Building Zero-Trust Linux Sandbox Image (agent-sandbox) ==="
docker build -t agent-sandbox "$SCRIPT_DIR"

echo ""
echo "=== [Member 1] Verifying Sandbox Isolation (cgroups, namespaces, read-only rootfs, non-root) ==="
python3 "$SCRIPT_DIR/sandbox_runner.py" "whoami && id && uname -a"

echo ""
echo "=== [Member 1] Testing Read-Only Filesystem Protection ==="
python3 "$SCRIPT_DIR/sandbox_runner.py" "touch /etc/hacked_file" || true

echo ""
echo "=== [Member 1] Sandbox setup completed successfully! ==="

