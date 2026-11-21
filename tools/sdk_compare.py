#!/usr/bin/env python3
"""Cross-SDK response comparison tool (Python boto3 vs JavaScript @aws-sdk v3).

Runs the exact same 7-service scenario suite on each SDK against rocalcloud,
normalizes responses and error codes, and reports any discrepancies.

Usage:
  uv run --with boto3 tools/sdk_compare.py
  uv run --with boto3 tools/sdk_compare.py --url http://127.0.0.1:4566 --out report.json
"""

import argparse
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parent.parent


# Known client-side error code aliases where boto3 maps a JSON __type to a legacy SQS code.
ERROR_ALIASES = {
    "AWS.SimpleQueueService.NonExistentQueue": "QueueDoesNotExist",
}


def capture_err(fn):
    try:
        fn()
        return None
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "UnknownError")
        return ERROR_ALIASES.get(code, code)


def run_python(url: str, region: str, tag: str) -> dict:
    kw = dict(endpoint_url=url, region_name=region, aws_access_key_id="test", aws_secret_access_key="test")
    out = {}

    # 1. STS
    sts = boto3.client("sts", **kw)
    who = sts.get_caller_identity()
    out["sts"] = {"account": who["Account"], "arn": who["Arn"]}

    # 2. DynamoDB
    ddb = boto3.client("dynamodb", **kw)
    t = f"cmp-ddb-{tag}"
    ddb.create_table(
        TableName=t, BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
    )
    ddb.put_item(TableName=t, Item={"pk": {"S": "u1"}, "sk": {"S": "o1"}, "total": {"N": "42"}})
    got = ddb.get_item(TableName=t, Key={"pk": {"S": "u1"}, "sk": {"S": "o1"}})
    q = ddb.query(
        TableName=t, KeyConditionExpression="pk = :p AND begins_with(sk, :s)",
        ExpressionAttributeValues={":p": {"S": "u1"}, ":s": {"S": "o"}},
    )
    cond_err = capture_err(lambda: ddb.put_item(
        TableName=t, Item={"pk": {"S": "u1"}, "sk": {"S": "o1"}}, ConditionExpression="attribute_not_exists(pk)"
    ))
    ddb.delete_table(TableName=t)
    out["dynamodb"] = {
        "get_total": got.get("Item", {}).get("total", {}).get("N"),
        "query_count": q["Count"],
        "cond_err": cond_err,
    }

    # 3. S3
    s3 = boto3.client("s3", config=Config(s3={"addressing_style": "path"}), **kw)
    b = f"cmp-s3-{tag}"
    s3.create_bucket(Bucket=b)
    s3.put_object(Bucket=b, Key="a/hello.txt", Body=b"hello-compare", ContentType="text/plain")
    body = s3.get_object(Bucket=b, Key="a/hello.txt")["Body"].read().decode()
    lst = s3.list_objects_v2(Bucket=b, Prefix="a/")
    miss_err = capture_err(lambda: s3.get_object(Bucket=b, Key="missing.txt"))
    s3.delete_object(Bucket=b, Key="a/hello.txt")
    s3.delete_bucket(Bucket=b)
    out["s3"] = {
        "body": body,
        "keys": [x["Key"] for x in lst.get("Contents", [])],
        "missing_err": miss_err,
    }

    # 4. SQS
    sqs = boto3.client("sqs", **kw)
    qn = f"cmp-sqs-{tag}"
    qurl = sqs.create_queue(QueueName=qn)["QueueUrl"]
    sqs.send_message(QueueUrl=qurl, MessageBody="msg-compare")
    rcv = sqs.receive_message(QueueUrl=qurl, MaxNumberOfMessages=1)
    msgs = rcv.get("Messages", [])
    msg_body = msgs[0]["Body"] if msgs else None
    if msgs:
        sqs.delete_message(QueueUrl=qurl, ReceiptHandle=msgs[0]["ReceiptHandle"])
    q_err = capture_err(lambda: sqs.get_queue_url(QueueName=f"nope-{tag}"))
    sqs.delete_queue(QueueUrl=qurl)
    out["sqs"] = {"body": msg_body, "missing_err": q_err}

    # 5. SNS
    sns = boto3.client("sns", **kw)
    tarn = sns.create_topic(Name=f"cmp-sns-{tag}")["TopicArn"]
    pub = sns.publish(TopicArn=tarn, Message="hi")
    sns.delete_topic(TopicArn=tarn)
    out["sns"] = {"has_message_id": bool(pub.get("MessageId")), "arn_suffix": tarn.endswith(f":cmp-sns-{tag}")}

    # 6. SSM
    ssm = boto3.client("ssm", **kw)
    pn = f"/cmp/{tag}/p"
    ssm.put_parameter(Name=pn, Value="v1", Type="String")
    pv = ssm.get_parameter(Name=pn)["Parameter"]
    ssm.delete_parameter(Name=pn)
    out["ssm"] = {"value": pv.get("Value"), "type": pv.get("Type")}

    # 7. Secrets Manager
    sm = boto3.client("secretsmanager", **kw)
    sn = f"cmp-sec-{tag}"
    sm.create_secret(Name=sn, SecretString='{"k":1}')
    sv = sm.get_secret_value(SecretId=sn)
    sm.delete_secret(SecretId=sn, ForceDeleteWithoutRecovery=True)
    out["secretsmanager"] = {"secret": sv.get("SecretString")}

    return out


def run_js(url: str, region: str, tag: str) -> dict:
    env = dict(os.environ, ROCALCLOUD_URL=url, REGION=region)
    script = ROOT / "tools" / "sdk_compare_js.mjs"
    p = subprocess.run(["node", str(script), tag], env=env, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"JS runner failed:\n{p.stderr or p.stdout}")
    return json.loads(p.stdout)


def diff_results(py_res: dict, js_res: dict) -> list:
    diffs = []
    for svc in sorted(set(py_res) | set(js_res)):
        a, b = py_res.get(svc), js_res.get(svc)
        if a != b:
            diffs.append({"service": svc, "python": a, "js": b})
    return diffs


def main():
    ap = argparse.ArgumentParser(description="Auto-compare official SDK responses against rocalcloud")
    ap.add_argument("--url", default=os.environ.get("ROCALCLOUD_URL", "http://127.0.0.1:4566"))
    ap.add_argument("--region", default=os.environ.get("REGION", "us-east-1"))
    ap.add_argument("--out", help="Write JSON comparison report to file")
    args = ap.parse_args()

    tag_py = "py" + secrets.token_hex(3)
    tag_js = "js" + secrets.token_hex(3)

    py_res = run_python(args.url, args.region, tag_py)
    js_res = run_js(args.url, args.region, tag_js)
    diffs = diff_results(py_res, js_res)

    print(f"{'Service':<16} {'Status':<10} Detail")
    print("-" * 64)
    for svc in sorted(set(py_res) | set(js_res)):
        ok = py_res.get(svc) == js_res.get(svc)
        detail = "identical" if ok else f"py={py_res.get(svc)} != js={js_res.get(svc)}"
        print(f"{svc:<16} {'MATCH' if ok else 'DIFF':<10} {detail}")

    report = {"url": args.url, "python": py_res, "js": js_res, "diffs": diffs, "passed": len(diffs) == 0}
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2, ensure_ascii=False))
        print(f"\nReport saved to {args.out}")

    if diffs:
        print(f"\nFAILED: {len(diffs)} service response mismatch(es)")
        sys.exit(1)
    print(f"\nPASSED: all {len(py_res)} services returned identical normalized responses across Python & JS SDKs.")


if __name__ == "__main__":
    main()
