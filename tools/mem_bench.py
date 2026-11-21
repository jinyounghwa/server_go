#!/usr/bin/env python3
"""Memory & throughput benchmark tool for rocalcloud.

Samples the rocalcloud process RSS (Linux /proc/<pid>/status or macOS ps) across
write / read / delete cycles on DynamoDB, S3, and SQS, reporting start/peak/end RSS,
net memory growth, and requests per second.

Usage:
  uv run --with boto3 tools/mem_bench.py
  uv run --with boto3 tools/mem_bench.py --cycles 500 --payload-kb 8 --max-growth-mb 64
"""

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

import boto3
from botocore.config import Config


def find_pid() -> int:
    out = subprocess.check_output(["pgrep", "-f", "rocalcloud"], text=True).strip().splitlines()
    me = os.getpid()
    for line in out:
        pid = int(line.strip())
        if pid != me:
            return pid
    raise RuntimeError("Could not find running rocalcloud process; pass --pid explicitly")


def rss_mb(pid: int) -> float:
    status = Path(f"/proc/{pid}/status")
    if status.exists():
        for line in status.read_text().splitlines():
            if line.startswith("VmRSS:"):
                return round(int(line.split()[1]) / 1024.0, 2)
    out = subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)], text=True).strip()
    return round(int(out) / 1024.0, 2)


def main():
    ap = argparse.ArgumentParser(description="rocalcloud RSS memory & throughput benchmark")
    ap.add_argument("--url", default=os.environ.get("ROCALCLOUD_URL", "http://127.0.0.1:4566").rstrip("/"))
    ap.add_argument("--pid", type=int, help="Target rocalcloud PID (auto-detected if omitted)")
    ap.add_argument("--cycles", type=int, default=300, help="Write/read/delete cycles per service")
    ap.add_argument("--payload-kb", type=int, default=4, help="Payload size in KiB")
    ap.add_argument("--max-growth-mb", type=float, default=64.0, help="Fail threshold for net RSS growth (MiB)")
    ap.add_argument("--out", help="Write JSON report to file")
    args = ap.parse_args()

    pid = args.pid or find_pid()
    kw = dict(endpoint_url=args.url, region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test")
    ddb = boto3.client("dynamodb", **kw)
    s3 = boto3.client("s3", config=Config(s3={"addressing_style": "path"}), **kw)
    sqs = boto3.client("sqs", **kw)

    tag = secrets.token_hex(3)
    table, bucket, qname = f"rc-mem-{tag}", f"rc-mem-{tag}", f"rc-mem-{tag}"
    payload = "x" * (args.payload_kb * 1024)
    payload_bytes = payload.encode()

    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
    )
    s3.create_bucket(Bucket=bucket)
    qurl = sqs.create_queue(QueueName=qname)["QueueUrl"]

    start_rss = rss_mb(pid)
    peak_rss = start_rss
    ops = 0
    t0 = time.perf_counter()
    samples = [{"step": "start", "rss_mb": start_rss}]

    try:
        # DynamoDB cycles
        for i in range(args.cycles):
            k = f"k-{i}"
            ddb.put_item(TableName=table, Item={"pk": {"S": k}, "data": {"S": payload}})
            ddb.get_item(TableName=table, Key={"pk": {"S": k}})
            ddb.delete_item(TableName=table, Key={"pk": {"S": k}})
            ops += 3
            if (i + 1) % max(1, args.cycles // 4) == 0:
                cur = rss_mb(pid)
                peak_rss = max(peak_rss, cur)
                samples.append({"step": f"ddb-{i+1}", "rss_mb": cur})

        # S3 cycles
        for i in range(args.cycles):
            k = f"obj-{i}.bin"
            s3.put_object(Bucket=bucket, Key=k, Body=payload_bytes)
            s3.get_object(Bucket=bucket, Key=k)["Body"].read()
            s3.delete_object(Bucket=bucket, Key=k)
            ops += 3
            if (i + 1) % max(1, args.cycles // 4) == 0:
                cur = rss_mb(pid)
                peak_rss = max(peak_rss, cur)
                samples.append({"step": f"s3-{i+1}", "rss_mb": cur})

        # SQS cycles
        for i in range(args.cycles):
            sqs.send_message(QueueUrl=qurl, MessageBody=payload[:1024])
            r = sqs.receive_message(QueueUrl=qurl, MaxNumberOfMessages=1)
            for m in r.get("Messages", []):
                sqs.delete_message(QueueUrl=qurl, ReceiptHandle=m["ReceiptHandle"])
            ops += 3
            if (i + 1) % max(1, args.cycles // 4) == 0:
                cur = rss_mb(pid)
                peak_rss = max(peak_rss, cur)
                samples.append({"step": f"sqs-{i+1}", "rss_mb": cur})
    finally:
        ddb.delete_table(TableName=table)
        s3.delete_bucket(Bucket=bucket)
        sqs.delete_queue(QueueUrl=qurl)

    elapsed = time.perf_counter() - t0
    end_rss = rss_mb(pid)
    peak_rss = max(peak_rss, end_rss)
    growth = round(end_rss - start_rss, 2)
    rps = round(ops / elapsed, 1) if elapsed > 0 else 0.0
    passed = growth <= args.max_growth_mb
    samples.append({"step": "end", "rss_mb": end_rss})

    print(f"PID {pid} | ops={ops} | elapsed={elapsed:.2f}s | RPS={rps}")
    print(f"RSS: start={start_rss} MiB, peak={peak_rss} MiB, end={end_rss} MiB, net_growth={growth:+.2f} MiB (limit {args.max_growth_mb} MiB)")

    report = {
        "pid": pid, "ops": ops, "elapsed_s": round(elapsed, 2), "rps": rps,
        "start_rss_mb": start_rss, "peak_rss_mb": peak_rss, "end_rss_mb": end_rss,
        "net_growth_mb": growth, "max_growth_mb": args.max_growth_mb,
        "passed": passed, "samples": samples,
    }
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2))
        print(f"Report saved to {args.out}")
    if not passed:
        print("FAILED: net RSS growth exceeded limit")
        sys.exit(1)
    print("PASSED: memory growth within bounds.")


if __name__ == "__main__":
    main()
