#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
cd ~/work/projects/rocalcloud

run_py() {
  if command -v uv >/dev/null 2>&1; then
    uv run --with boto3 "$@"
  else
    python3 "$@"
  fi
}

echo "=== 1. Rust unit tests & release build (nice -n 10, -j 8) ==="
(cd core && nice -n 10 ~/.cargo/bin/cargo test -j 8 && nice -n 10 ~/.cargo/bin/cargo build --release -j 8)

if [ ! -d tests/js/node_modules ]; then
  echo "=== 2. Installing JS SDK dependencies ==="
  (cd tests/js && npm install --no-audit --no-fund)
fi

echo "=== 3. Starting rocalcloud with ENFORCE_IAM=1 & RC_SQLITE_FILE ==="
DB="/tmp/rc_verify_$$.db"
rm -f "$DB" "$DB-wal" "$DB-shm"
ENFORCE_IAM=1 RC_SQLITE_FILE="$DB" ./core/target/release/rocalcloud >/tmp/rc_verify.log 2>&1 &
SRV_PID=$!
cleanup() {
  kill -TERM "$SRV_PID" 2>/dev/null || true
  wait "$SRV_PID" 2>/dev/null || true
  rm -f "$DB" "$DB-wal" "$DB-shm"
}
trap cleanup EXIT

for _ in $(seq 1 30); do
  if curl -sf http://127.0.0.1:4566/_admin/state >/dev/null 2>&1; then break; fi
  sleep 0.2
done

echo "=== 4. Cross-SDK response comparison (Python vs JS) ==="
run_py tools/sdk_compare.py

echo "=== 5. Partial failure & chaos recovery check ==="
run_py tools/partial_fail_check.py --rates 0.2,0.5 --samples 40 --latency-ms 30

echo "=== 6. Memory & throughput benchmark ==="
run_py tools/mem_bench.py --pid "$SRV_PID" --cycles 100 --payload-kb 4

echo "=== 7. SQLite snapshot & unified DB query CLI check ==="
curl -sf -X POST -H "x-rocalcloud: 1" -H "Content-Type: application/json" \
  -d '{"label":"ubuntu-verify"}' http://127.0.0.1:4566/_admin/sqlite/save
echo ""
run_py tools/db_query.py sqlite "SELECT service, count(*) AS cnt FROM events GROUP BY service ORDER BY cnt DESC LIMIT 10"
run_py tools/db_query.py sqlite "SELECT id, label, length(payload) AS bytes FROM snapshots ORDER BY id DESC LIMIT 5"

echo "=== 8. Graceful shutdown & leftover container check ==="
kill -TERM "$SRV_PID"
wait "$SRV_PID" || true
docker ps -a --filter "name=rocalcloud-"
echo "ALL CHECKS PASSED"
