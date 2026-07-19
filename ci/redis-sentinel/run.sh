#!/usr/bin/env bash
# Run the PR2c Redis Sentinel failover drill. The drill runs as an in-network compose service so
# it reaches master/replica/sentinels by name (no host-NAT). We DON'T use --abort-on-container-exit
# because the drill intentionally crashes the master (its container exits) mid-run; instead we
# `docker wait` on the drill container and propagate ITS exit code. Portable: CI (ubuntu) + local.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
export TSK_REPO="${TSK_REPO:-$(cd "$DIR/../.." && pwd)}"
cd "$DIR"
compose() { docker compose -p tsk-sentinel "$@"; }

cleanup() { compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

compose up -d --build
cid="$(compose ps -q drill)"
[ -n "$cid" ] || { echo "drill container did not start"; compose logs; exit 1; }

code="$(docker wait "$cid")"
compose logs --no-color drill
echo "── drill exit code: $code ──"
exit "$code"
