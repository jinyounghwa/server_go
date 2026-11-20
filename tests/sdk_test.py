"""Official-SDK (boto3) compatibility check. Run: uv run --with boto3 tests/sdk_test.py
Expects the emulator on ENDPOINT (default http://127.0.0.1:4566)."""
import json, os, time, uuid
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

EP = os.environ.get("ENDPOINT", "http://127.0.0.1:4566")
kw = dict(endpoint_url=EP, region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test")
ddb = boto3.client("dynamodb", **kw)
s3 = boto3.client("s3", config=Config(s3={"addressing_style": "path"}), **kw)
sqs = boto3.client("sqs", **kw)
run = uuid.uuid4().hex[:8]


def code(fn, *a, **k):
    try:
        fn(*a, **k)
    except ClientError as e:
        return e.response["Error"]["Code"]
    raise AssertionError("expected error")


def test_dynamodb():
    t = f"t{run}"
    ddb.create_table(TableName=t, BillingMode="PAY_PER_REQUEST",
                     KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
                     AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S" if n != "sk" else "N"} for n in ("pk", "sk", "g")],
                     GlobalSecondaryIndexes=[{"IndexName": "byg", "KeySchema": [{"AttributeName": "g", "KeyType": "HASH"}],
                                              "Projection": {"ProjectionType": "ALL"}}])
    ddb.get_waiter("table_exists").wait(TableName=t)
    assert t in ddb.list_tables()["TableNames"]
    assert code(ddb.create_table, TableName=t, KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}], BillingMode="PAY_PER_REQUEST") == "ResourceInUseException"

    for i in range(5):
        ddb.put_item(TableName=t, Item={"pk": {"S": "u1"}, "sk": {"N": str(i)}, "g": {"S": "even" if i % 2 == 0 else "odd"}, "n": {"N": "0"}})
    assert code(ddb.put_item, TableName=t, Item={"pk": {"S": "u1"}, "sk": {"N": "0"}},
                ConditionExpression="attribute_not_exists(pk)") == "ConditionalCheckFailedException"
    assert ddb.get_item(TableName=t, Key={"pk": {"S": "u1"}, "sk": {"N": "3"}})["Item"]["g"] == {"S": "odd"}
    assert "Item" not in ddb.get_item(TableName=t, Key={"pk": {"S": "nope"}, "sk": {"N": "1"}})

    q = ddb.query(TableName=t, KeyConditionExpression="pk = :p AND sk BETWEEN :a AND :b",
                  ExpressionAttributeValues={":p": {"S": "u1"}, ":a": {"N": "1"}, ":b": {"N": "3"}}, ScanIndexForward=False)
    assert [i["sk"]["N"] for i in q["Items"]] == ["3", "2", "1"], q

    # pagination via paginator (Limit + LastEvaluatedKey)
    pages = ddb.get_paginator("query").paginate(TableName=t, KeyConditionExpression="#p = :p",
                                                 ExpressionAttributeNames={"#p": "pk"}, ExpressionAttributeValues={":p": {"S": "u1"}},
                                                 PaginationConfig={"PageSize": 2})
    assert [i["sk"]["N"] for p in pages for i in p["Items"]] == ["0", "1", "2", "3", "4"]

    g = ddb.query(TableName=t, IndexName="byg", KeyConditionExpression="g = :g", ExpressionAttributeValues={":g": {"S": "even"}})
    assert g["Count"] == 3
    f = ddb.scan(TableName=t, FilterExpression="g = :g AND sk > :z", ExpressionAttributeValues={":g": {"S": "odd"}, ":z": {"N": "1"}})
    assert f["Count"] == 1 and f["ScannedCount"] == 5

    u = ddb.update_item(TableName=t, Key={"pk": {"S": "u1"}, "sk": {"N": "1"}},
                        UpdateExpression="SET n = n + :one, tags = list_append(if_not_exists(tags, :e), :t) REMOVE g ADD s :s",
                        ExpressionAttributeValues={":one": {"N": "1"}, ":e": {"L": []}, ":t": {"L": [{"S": "x"}]}, ":s": {"SS": ["a"]}},
                        ReturnValues="ALL_NEW")["Attributes"]
    assert u["n"] == {"N": "1"} and u["tags"] == {"L": [{"S": "x"}]} and "g" not in u and u["s"] == {"SS": ["a"]}, u

    assert code(ddb.transact_write_items, TransactItems=[
        {"Put": {"TableName": t, "Item": {"pk": {"S": "tx"}, "sk": {"N": "1"}}}},
        {"ConditionCheck": {"TableName": t, "Key": {"pk": {"S": "u1"}, "sk": {"N": "1"}}, "ConditionExpression": "n = :x",
                            "ExpressionAttributeValues": {":x": {"N": "99"}}}}]) == "TransactionCanceledException"
    assert "Item" not in ddb.get_item(TableName=t, Key={"pk": {"S": "tx"}, "sk": {"N": "1"}}), "transaction must roll back"

    ddb.batch_write_item(RequestItems={t: [{"DeleteRequest": {"Key": {"pk": {"S": "u1"}, "sk": {"N": str(i)}}}} for i in range(5)]})
    assert ddb.scan(TableName=t, Select="COUNT")["Count"] == 0
    ddb.delete_table(TableName=t)
    assert code(ddb.describe_table, TableName=t) == "ResourceNotFoundException"


def test_s3():
    b = f"b{run}"
    s3.create_bucket(Bucket=b)
    assert b in [x["Name"] for x in s3.list_buckets()["Buckets"]]
    s3.put_object(Bucket=b, Key="dir/a.txt", Body=b"hello", ContentType="text/plain", Metadata={"who": "me"})
    s3.put_object(Bucket=b, Key="dir/sub/b.txt", Body=b"x")
    s3.put_object(Bucket=b, Key="top key+?.txt", Body=b"y")
    o = s3.get_object(Bucket=b, Key="dir/a.txt")
    assert o["Body"].read() == b"hello" and o["ContentType"] == "text/plain" and o["Metadata"] == {"who": "me"}
    assert s3.get_object(Bucket=b, Key="dir/a.txt", Range="bytes=1-3")["Body"].read() == b"ell"
    assert s3.head_object(Bucket=b, Key="dir/a.txt")["ContentLength"] == 5
    assert s3.get_object(Bucket=b, Key="top key+?.txt")["Body"].read() == b"y"
    assert code(s3.get_object, Bucket=b, Key="missing") == "NoSuchKey"

    l = s3.list_objects_v2(Bucket=b, Prefix="dir/", Delimiter="/")
    assert [c["Key"] for c in l["Contents"]] == ["dir/a.txt"] and [p["Prefix"] for p in l["CommonPrefixes"]] == ["dir/sub/"], l
    keys = [c["Key"] for p in s3.get_paginator("list_objects_v2").paginate(Bucket=b, PaginationConfig={"PageSize": 1}) for c in p.get("Contents", [])]
    assert keys == ["dir/a.txt", "dir/sub/b.txt", "top key+?.txt"], keys

    s3.copy_object(Bucket=b, Key="copy.txt", CopySource={"Bucket": b, "Key": "dir/a.txt"})
    assert s3.get_object(Bucket=b, Key="copy.txt")["Body"].read() == b"hello"

    # multipart via the high-level transfer manager (12 MiB > 8 MiB threshold)
    big = os.urandom(12 * 1024 * 1024)
    path = f"/tmp/rocalcloud-{run}.bin"
    with open(path, "wb") as fh:
        fh.write(big)
    s3.upload_file(path, b, "big.bin")
    s3.download_file(b, "big.bin", path + ".out")
    with open(path + ".out", "rb") as fh:
        assert fh.read() == big
    os.remove(path); os.remove(path + ".out")

    import urllib.request
    url = s3.generate_presigned_url("get_object", Params={"Bucket": b, "Key": "dir/a.txt"})
    assert urllib.request.urlopen(url).read() == b"hello"

    assert code(s3.delete_bucket, Bucket=b) == "BucketNotEmpty"
    allk = [c["Key"] for c in s3.list_objects_v2(Bucket=b)["Contents"]]
    s3.delete_objects(Bucket=b, Delete={"Objects": [{"Key": k} for k in allk]})
    s3.delete_bucket(Bucket=b)
    assert code(s3.head_bucket, Bucket=b) == "404"


def test_sqs():
    dlq = sqs.create_queue(QueueName=f"dlq{run}")["QueueUrl"]
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    q = sqs.create_queue(QueueName=f"q{run}", Attributes={
        "VisibilityTimeout": "1", "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": "2"})})["QueueUrl"]
    assert sqs.get_queue_url(QueueName=f"q{run}")["QueueUrl"] == q
    try:
        sqs.get_queue_url(QueueName="nope")
        raise AssertionError
    except sqs.exceptions.QueueDoesNotExist:
        pass

    sqs.send_message(QueueUrl=q, MessageBody="hi")  # boto3 verifies MD5OfMessageBody
    r = sqs.receive_message(QueueUrl=q, MessageSystemAttributeNames=["All"])["Messages"]
    assert r[0]["Body"] == "hi" and r[0]["Attributes"]["ApproximateReceiveCount"] == "1"
    assert "Messages" not in sqs.receive_message(QueueUrl=q), "invisible during visibility timeout"
    t0 = time.time()
    again = sqs.receive_message(QueueUrl=q, WaitTimeSeconds=3)["Messages"]  # long poll until it reappears
    assert again[0]["Body"] == "hi" and time.time() - t0 < 3
    time.sleep(1.1)
    assert "Messages" not in sqs.receive_message(QueueUrl=q), "3rd receive moves it to DLQ"
    assert sqs.receive_message(QueueUrl=dlq)["Messages"][0]["Body"] == "hi"

    sqs.send_message_batch(QueueUrl=q, Entries=[{"Id": str(i), "MessageBody": f"m{i}"} for i in range(3)])
    msgs = sqs.receive_message(QueueUrl=q, MaxNumberOfMessages=10)["Messages"]
    assert [m["Body"] for m in msgs] == ["m0", "m1", "m2"]
    sqs.delete_message_batch(QueueUrl=q, Entries=[{"Id": m["MessageId"], "ReceiptHandle": m["ReceiptHandle"]} for m in msgs])
    time.sleep(1.1)
    a = sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["All"])["Attributes"]
    assert a["ApproximateNumberOfMessages"] == "0", a
    sqs.delete_queue(QueueUrl=q); sqs.delete_queue(QueueUrl=dlq)
    assert q not in sqs.list_queues().get("QueueUrls", [])


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
