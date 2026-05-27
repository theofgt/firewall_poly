#!/usr/bin/env bash
# run_tests.sh
# Orchestrate the correctness test suite for the firewall-polymorphism pipeline.
#
# Prerequisites:
#   docker compose up -d    (all services running)
#
# Usage:
#   ./run_tests.sh                 # run all tests
#   ./run_tests.sh --test session  # run one test
#
# The script temporarily stops the client and server traffic-gen containers
# so that the embedded test server has exclusive access to veth-server.
# They are restarted (or left stopped) when the script exits.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="${SCRIPT_DIR}/../docker"
COMPOSE_FILE="${COMPOSE_DIR}/docker-compose.yml"
TEST_SCRIPT="${SCRIPT_DIR}/correctness_test.py"

log()  { echo "[run_tests] $*"; }
die()  { echo "[run_tests] ERROR: $*" >&2; exit 1; }

# ── Sanity checks ──────────────────────────────────────────────────────────────
[[ -f "$COMPOSE_FILE" ]] || die "docker-compose.yml not found at $COMPOSE_FILE"
[[ -f "$TEST_SCRIPT"  ]] || die "correctness_test.py not found at $TEST_SCRIPT"
command -v docker &>/dev/null || die "docker not found in PATH"

# ── Wait for the pipeline ──────────────────────────────────────────────────────
log "Waiting for load_balancer to become healthy …"
for i in $(seq 1 90); do
    status=$(docker inspect --format='{{.State.Health.Status}}' load_balancer 2>/dev/null || true)
    [[ "$status" == "healthy" ]] && break
    sleep 1
done
status=$(docker inspect --format='{{.State.Health.Status}}' load_balancer 2>/dev/null || true)
[[ "$status" == "healthy" ]] || die "load_balancer did not become healthy within 90 s"
log "load_balancer is healthy"

sleep 3

# ── Pause traffic-gen containers ──────────────────────────────────────────────
log "Stopping client and server containers for the duration of the tests …"
docker compose -f "$COMPOSE_FILE" stop client server 2>/dev/null || true

cleanup() {
    log "Restarting client and server …"
    docker compose -f "$COMPOSE_FILE" start client server 2>/dev/null || true
}
trap cleanup EXIT

# ── Ensure the traffic-gen image is available ─────────────────────────────────
if ! docker image inspect traffic-gen:latest &>/dev/null; then
    log "Building traffic-gen image …"
    docker compose -f "$COMPOSE_FILE" build --quiet 2>/dev/null || \
        docker build -f "${COMPOSE_DIR}/Dockerfile" \
                     --target traffic-gen \
                     -t traffic-gen:latest \
                     "${COMPOSE_DIR}/.."
fi

# ── Run the test container ────────────────────────────────────────────────────
log "Launching correctness_test.py …"
docker run --rm \
    --privileged \
    --network host \
    --pid host \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v "${TEST_SCRIPT}:/test/correctness_test.py:ro" \
    --entrypoint python3 \
    traffic-gen:latest \
    /test/correctness_test.py "$@"
