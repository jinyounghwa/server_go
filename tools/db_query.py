#!/usr/bin/env python3
"""Unified DB query CLI for rocalcloud (SQLite / DynamoDB / RDS / Redis).

Examples:
  uv run --with boto3 tools/db_query.py sqlite "SELECT service, count(*) FROM events GROUP BY service"
  uv run --with boto3 tools/db_query.py sqlite --schema
  uv run --with boto3 tools/db_query.py ddb tables
  uv run --with boto3 tools/db_query.py ddb scan orders --limit 20
  uv run --with boto3 tools/db_query.py ddb query orders --key pk=u1
  uv run --with boto3 --with pg8000 --with pymysql tools/db_query.py rds list
  uv run --with boto3 --with pg8000 tools/db_query.py rds query mydb "SELECT 1"
  uv run --with boto3 --with redis tools/db_query.py redis list
  uv run --with boto3 --with redis tools/db_query.py redis cmd mycache PING
"""

import argparse
import json
import os
import sqlite3
import sys
import urllib.error
import urllib.request

DEFAULT_URL = os.environ.get("ROCALCLOUD_URL", "http://127.0.0.1:4566").rstrip("/")
REGION = os.environ.get("REGION", "us-east-1")


def print_table(cols, rows, as_json=False):
    if as_json:
        print(json.dumps([dict(zip(cols, r)) for r in rows], ensure_ascii=False, indent=2, default=str))
        return
    if not cols:
        print("(no columns)")
        return
    str_rows = [[("NULL" if v is None else str(v)) for v in r] for r in rows]
    widths = [max(len(str(c)), max((len(r[i]) for r in str_rows), default=0)) for i, c in enumerate(cols)]
    widths = [min(w, 60) for w in widths]
    fmt = " | ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*[str(c)[:w] for c, w in zip(cols, widths)]))
    print("-+-".join("-" * w for w in widths))
    for r in str_rows:
        print(fmt.format(*[v.replace("\n", " ")[:w] for v, w in zip(r, widths)]))
    print(f"({len(rows)} rows)")


def cmd_sqlite(args):
    sql = args.sql
    if args.schema:
        sql = "SELECT name, type, sql FROM sqlite_master WHERE type IN ('table','index') ORDER BY type, name"
    if not sql:
        sys.exit("Provide a SQL query or --schema")

    if args.file:
        conn = sqlite3.connect(f"file:{args.file}?mode=ro", uri=True)
        try:
            cur = conn.execute(sql)
            cols = [d[0] for d in (cur.description or [])]
            rows = cur.fetchmany(args.limit)
            print_table(cols, rows, args.json)
        finally:
            conn.close()
        return

    req = urllib.request.Request(
        f"{args.url}/_admin/sql",
        data=json.dumps({"sql": sql, "limit": args.limit}).encode(),
        headers={"Content-Type": "application/json", "x-rocalcloud": "1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        sys.exit(f"SQL error ({e.code}): {e.read().decode()}")
    print_table(data["columns"], data["rows"], args.json)
    if not args.json:
        print(f"elapsed: {data.get('elapsed_ms')}ms" + (" [truncated]" if data.get("truncated") else ""))


def _boto_client(service, url):
    import boto3
    return boto3.client(
        service,
        endpoint_url=url,
        region_name=REGION,
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
    )


def _unmarshal(item):
    out = {}
    for k, v in item.items():
        if "S" in v:
            out[k] = v["S"]
        elif "N" in v:
            out[k] = v["N"]
        elif "BOOL" in v:
            out[k] = v["BOOL"]
        elif "NULL" in v:
            out[k] = None
        else:
            out[k] = v
    return out


def cmd_ddb(args):
    ddb = _boto_client("dynamodb", args.url)
    if args.action == "tables":
        names = ddb.list_tables().get("TableNames", [])
        if args.json:
            print(json.dumps(names, indent=2))
        else:
            print_table(["TableName"], [[n] for n in names])
        return
    if not args.table:
        sys.exit("Table name is required for scan/query")
    if args.action == "scan":
        resp = ddb.scan(TableName=args.table, Limit=args.limit)
        items = [_unmarshal(i) for i in resp.get("Items", [])]
    elif args.action == "query":
        if not args.key or "=" not in args.key:
            sys.exit("--key attr=value is required for query")
        k, v = args.key.split("=", 1)
        av = {"N": v} if args.num else {"S": v}
        resp = ddb.query(
            TableName=args.table,
            KeyConditionExpression="#k = :v",
            ExpressionAttributeNames={"#k": k},
            ExpressionAttributeValues={":v": av},
            Limit=args.limit,
        )
        items = [_unmarshal(i) for i in resp.get("Items", [])]
    else:
        sys.exit(f"Unknown ddb action: {args.action}")
    if args.json:
        print(json.dumps(items, ensure_ascii=False, indent=2, default=str))
        return
    cols = sorted({k for it in items for k in it.keys()})
    rows = [[it.get(c) for c in cols] for it in items]
    print_table(cols, rows)


def cmd_rds(args):
    rds = _boto_client("rds", args.url)
    dbs = rds.describe_db_instances().get("DBInstances", [])
    if args.action == "list":
        rows = [[d["DBInstanceIdentifier"], d.get("Engine"), d.get("DBInstanceStatus"),
                 f"{d.get('Endpoint', {}).get('Address', '')}:{d.get('Endpoint', {}).get('Port', '')}"] for d in dbs]
        print_table(["Identifier", "Engine", "Status", "Endpoint"], rows, args.json)
        return
    match = [d for d in dbs if d["DBInstanceIdentifier"] == args.instance]
    if not match:
        sys.exit(f"RDS instance not found: {args.instance}")
    inst = match[0]
    ep = inst.get("Endpoint", {})
    host, port = ep.get("Address", "127.0.0.1"), int(ep.get("Port", 5432))
    engine = (inst.get("Engine") or "").lower()
    user = args.user or inst.get("MasterUsername") or "postgres"
    password = args.password or os.environ.get("RDS_PASSWORD", "postgres")
    dbname = args.db or inst.get("DBName") or ("postgres" if "postgres" in engine else "mysql")

    if "postgres" in engine:
        import pg8000.native
        con = pg8000.native.Connection(user=user, password=password, host=host, port=port, database=dbname)
        try:
            rows = con.run(args.sql)
            cols = [c["name"] for c in (con.columns or [])]
            print_table(cols, rows[: args.limit], args.json)
        finally:
            con.close()
    else:
        import pymysql
        con = pymysql.connect(host=host, port=port, user=user, password=password, database=dbname)
        try:
            with con.cursor() as cur:
                cur.execute(args.sql)
                cols = [d[0] for d in (cur.description or [])]
                rows = cur.fetchmany(args.limit)
                print_table(cols, rows, args.json)
        finally:
            con.close()


def cmd_redis(args):
    ec = _boto_client("elasticache", args.url)
    clusters = ec.describe_cache_clusters(ShowCacheNodeInfo=True).get("CacheClusters", [])
    if args.action == "list":
        rows = []
        for c in clusters:
            nodes = c.get("CacheNodes") or [{}]
            ep = nodes[0].get("Endpoint", {})
            rows.append([c["CacheClusterId"], c.get("Engine"), c.get("CacheClusterStatus"),
                         f"{ep.get('Address', '')}:{ep.get('Port', '')}"])
        print_table(["ClusterId", "Engine", "Status", "Endpoint"], rows, args.json)
        return
    match = [c for c in clusters if c["CacheClusterId"] == args.cluster]
    if not match:
        sys.exit(f"Cache cluster not found: {args.cluster}")
    ep = (match[0].get("CacheNodes") or [{}])[0].get("Endpoint", {})
    import redis
    r = redis.Redis(host=ep.get("Address", "127.0.0.1"), port=int(ep.get("Port", 6379)), decode_responses=True)
    res = r.execute_command(*args.command)
    print(json.dumps(res, ensure_ascii=False, indent=2, default=str) if args.json else res)


def main():
    p = argparse.ArgumentParser(description="rocalcloud unified DB query CLI")
    p.add_argument("--url", default=DEFAULT_URL, help="rocalcloud endpoint (default: http://127.0.0.1:4566)")
    p.add_argument("--json", action="store_true", help="Output JSON")
    p.add_argument("--limit", type=int, default=100, help="Max rows")
    sub = p.add_subparsers(dest="kind", required=True)

    ps = sub.add_parser("sqlite", help="Query rocalcloud SQLite store (via /_admin/sql or local --file)")
    ps.add_argument("sql", nargs="?", help="Read-only SELECT query")
    ps.add_argument("--schema", action="store_true", help="Show SQLite schema")
    ps.add_argument("--file", help="Query a local SQLite DB file directly (read-only)")
    ps.set_defaults(func=cmd_sqlite)

    pd = sub.add_parser("ddb", help="Query/Scan DynamoDB tables")
    pd.add_argument("action", choices=["tables", "scan", "query"])
    pd.add_argument("table", nargs="?")
    pd.add_argument("--key", help="Partition key filter for query, e.g. pk=u1")
    pd.add_argument("--num", action="store_true", help="Treat --key value as DynamoDB Number (N)")
    pd.set_defaults(func=cmd_ddb)

    pr = sub.add_parser("rds", help="List or query Docker-backed RDS instances")
    pr.add_argument("action", choices=["list", "query"])
    pr.add_argument("instance", nargs="?")
    pr.add_argument("sql", nargs="?")
    pr.add_argument("--user")
    pr.add_argument("--password")
    pr.add_argument("--db")
    pr.set_defaults(func=cmd_rds)

    pc = sub.add_parser("redis", help="List or run commands on Docker-backed ElastiCache Redis")
    pc.add_argument("action", choices=["list", "cmd"])
    pc.add_argument("cluster", nargs="?")
    pc.add_argument("command", nargs="*")
    pc.set_defaults(func=cmd_redis)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
