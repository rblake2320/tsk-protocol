#!/usr/bin/env bash
# Bring up the Redis Sentinel topology (1 master + 2 replicas + 3 sentinels), then run ONE PR2c drill
# ON THE HOST (so it can drive `docker network disconnect` for a live partition, and use ioredis natMap
# to follow Sentinel failover through the published ports). A fresh topology per drill invocation.
# Usage: run.sh <drill.mts>
set -euo pipefail
DRILL="${1:?usage: run.sh <drill.mts>}"
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
compose() { (cd "$DIR" && docker compose -p tsk-sentinel "$@"); }
cleanup() { compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
compose up -d

echo "waiting for sentinels to see master + 2 replicas..."
ok=0
for _ in $(seq 1 60); do
  n="$(docker exec tsk-sentinel-sentinel-1-1 redis-cli -p 26379 sentinel master tskmaster 2>/dev/null | awk '/num-slaves/{getline; print}' | tr -d '\r' || echo 0)"
  if [ "${n:-0}" -ge 2 ]; then ok=1; break; fi
  sleep 1
done
[ "$ok" = 1 ] || { echo "topology did not converge (num-slaves<2)"; compose ps; exit 1; }
# ensure both replicas are CAUGHT UP (min-replicas-to-write would otherwise reject the first durable claim).
docker exec tsk-sentinel-redis-master-1 redis-cli WAIT 2 10000 >/dev/null || true

export TSK_TEST_SENTINELS="127.0.0.1:26379,127.0.0.1:26380,127.0.0.1:26381"
export TSK_TEST_SENTINEL_MASTER="tskmaster"
export TSK_SENTINEL_NATMAP="172.28.7.10:6379=127.0.0.1:6390,172.28.7.11:6379=127.0.0.1:6391,172.28.7.12:6379=127.0.0.1:6392"
export TSK_SENTINEL_NETWORK="tsk-sentinel_tsknet"
export TSK_SENTINEL_MASTER_CONTAINER="tsk-sentinel-redis-master-1"
export TSK_SENTINEL_MASTER_PORT="6390"

cd "$ROOT"
node --import tsx "$DRILL"
