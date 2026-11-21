#!/usr/bin/env python3
"""Partial failure & chaos recovery diagnostic tool for rocalcloud.

Injects configurable error/throttle rates and latency via /_admin/chaos, sends concurrent
requests, checks observed vs expected failure rates, latency percentiles, and verifies
100% clean recovery after clearing chaos rules.

Usage:
  uv run --with boto3 tools/partial_fail_check.py
  uv run --with boto3 tools/partial_fail_check.py --rates 0.2,0.5 --samples 60 --latency-ms 40
"""

import argparse
import concurrent.futures
import json
import os
import secrets
import statistics
import sys
import time
import urllib.request
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def set_chaos(url: str, rules: list):
    req = urllib.request.Request(
        f"{url}/_admin/chaos",
        data=json.dumps({"rules": rules}).encode(),
        headers={"Content-Type": "application/json", "x-rocalcloud": "1"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status in (200, 204)


def percentile(vals, p):
    if not vals:
        return 0.0
    s = sorted(vals)
    idx = min(len(s) - 1, max(0, int(round((p / 100.0) * (len(s) - 1)))))
    return round(s[idx], 2)


def run_batch(ddb, table: str, n: int, workers: int):
    latencies = []
    ok = err5xx = throttled = other = 0

    def one(_):
        t0 = time.perf_counter()
        try:
            ddb.get_item(TableName=table, Key={"pk": {"S": "k1"}})
            return ("ok", (time.perf_counter() - t0) * 1000.0)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            status = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
            ms = (time.perf_counter() - t0) * 1000.0
            if "Throttl" in code or "Throughput" in code:
                return ("throttle", ms)
            if status >= 500:
                return ("5xx", ms)
            return ("other", ms)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for kind, ms in ex.map(one, range(n)):
            latencies.append(ms)
            if kind == "ok":
                ok += 1
            elif kind == "5xx":
                err5xx += 1
            elif kind == "throttle":
                throttled += 1
            else:
                other += 1
    return {
        "total": n, "ok": ok, "err5xx": err5xx, "throttled": throttled, "other": other,
        "fail_rate": round((n - ok) / n, 3),
        "p50_ms": percentile(latencies, 50),
        "p95_ms": percentile(latencies, 95),
        "p99_ms": percentile(latencies, 99),
        "avg_ms": round(statistics.mean(latencies), 2) if latencies else 0.0,
    }


def main():
    ap = argparse.ArgumentParser(description="Partial failure & chaos recovery checker")
    ap.add_argument("--url", default=os.environ.get("ROCALCLOUD_URL", "http://127.0.0.1:4566").rstrip("/"))
    ap.add_argument("--rates", default="0.2,0.5", help="Comma-separated error rates to test")
    ap.add_argument("--samples", type=int, default=60, help="Requests per phase")
    ap.add_argument("--workers", type=int, default=8, help="Concurrent workers")
    ap.add_argument("--latency-ms", type=int, default=30, help="Injected latency in ms")
    ap.add_argument("--out", help="Write JSON report to file")
    args = ap.parse_args()

    ddb = boto3.client(
        "dynamodb", endpoint_url=args.url, region_name="us-east-1",
        aws_access_key_id="test", aws_secret_access_key="test",
        config=Config(retries={"mode": "standard", "total_max_attempts": 1}),
    )
    table = f"rc-pfail-{secrets.token_hex(3)}"
    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
    )
    ddb.put_item(TableName=table, Item={"pk": {"S": "k1"}, "v": {"S": "hello"}})

    phases = []
    passed = True
    try:
        for rate in [float(x) for x in args.rates.split(",") if x.strip()]:
            # Error-rate phase
            set_chaos(args.url, [{"service": "dynamodb", "op": "GetItem", "error_rate": rate, "latency_ms": args.latency_ms}])
            res = run_batch(ddb, table, args.samples, args.workers)
            tol = 0.25
            ok_phase = abs(res["fail_rate"] - rate) <= tol and res["p50_ms"] >= args.latency_ms * 0.7
            passed = passed and ok_phase
            phases.append({"phase": f"error_rate={rate}", "expected_rate": rate, "passed": ok_phase, **res})

            # Throttle-rate phase
            set_chaos(args.url, [{"service": "dynamodb", "op": "GetItem", "throttle_rate": rate}])
            res_t = run_batch(ddb, table, args.samples, args.workers)
            ok_t = abs(res_t["fail_rate"] - rate) <= tol and res_t["throttled"] > 0
            passed = passed and ok_t
            phases.append({"phase": f"throttle_rate={rate}", "expected_rate": rate, "passed": ok_t, **res_t})

        # Recovery phase
        set_chaos(args.url, [])
        rec = run_batch(ddb, table, max(20, args.samples // 2), args.workers)
        ok_rec = rec["ok"] == rec["total"]
        passed = passed and ok_rec
        phases.append({"phase": "recovery", "expected_rate": 0.0, "passed": ok_rec, **rec})
    finally:
        set_chaos(args.url, [])
        ddb.delete_table(TableName=table)

    print(f"{'Phase':<22} {'Pass':<6} {'OK/Tot':<10} {'FailRate':<10} {'5xx':<5} {'Throt':<6} {'p50ms':<8} {'p95ms':<8}")
    print("-" * 82)
    for ph in phases:
        print(f"{ph['phase']:<22} {'PASS' if ph['passed'] else 'FAIL':<6} {ph['ok']}/{ph['total']:<7} "
              f"{ph['fail_rate']:<10.3f} {ph['err5xx']:<5} {ph['throttled']:<6} {ph['p50_ms']:<8} {ph['p95_ms']:<8}")

    report = {"url": args.url, "passed": passed, "phases": phases}
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2))
        print(f"\nReport saved to {args.out}")
    if not passed:
        sys.exit(1)
    print("\nPASSED: partial failure rates, latency, and clean recovery verified.")


if __name__ == "__main__":
    main()
