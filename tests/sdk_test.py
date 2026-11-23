"""Official-SDK (boto3) compatibility check. Run: uv run --with boto3 tests/sdk_test.py
Expects the emulator on ENDPOINT (default http://127.0.0.1:4566) started with ENFORCE_IAM=1.
Run: uv run --with boto3 --with "pyjwt[crypto]" --with pg8000 --with pymysql --with redis --with dnspython tests/sdk_test.py
test_rds_elasticache needs Docker on the emulator host and is skipped without it."""
import json, os, time, uuid
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

EP = os.environ.get("ENDPOINT", "http://127.0.0.1:4566")
kw = dict(endpoint_url=EP, region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test")
ddb = boto3.client("dynamodb", **kw)
s3 = boto3.client("s3", config=Config(signature_version="s3v4", s3={"addressing_style": "path"}), **kw)
sqs = boto3.client("sqs", **kw)
run = uuid.uuid4().hex[:8]


class Skip(Exception):
    pass


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

    # list[index] document paths in update, condition and projection expressions
    lk = {"pk": {"S": "lists"}, "sk": {"N": "1"}}
    ddb.put_item(TableName=t, Item={**lk, "tags": {"L": [{"S": "a"}, {"S": "b"}, {"S": "c"}]}, "doc": {"M": {"rows": {"L": [{"M": {"n": {"N": "1"}}}]}}}})
    ddb.update_item(TableName=t, Key=lk, UpdateExpression="SET tags[0] = :x, doc.rows[0].n = doc.rows[0].n + :one REMOVE tags[2]",
                    ConditionExpression="tags[1] = :b", ExpressionAttributeValues={":x": {"S": "z"}, ":one": {"N": "1"}, ":b": {"S": "b"}})
    got = ddb.get_item(TableName=t, Key=lk, ProjectionExpression="tags[1], doc.rows[0].n")["Item"]
    assert got == {"tags": {"L": [{"S": "b"}]}, "doc": {"M": {"rows": {"L": [{"M": {"n": {"N": "2"}}}]}}}}, got
    assert ddb.get_item(TableName=t, Key=lk)["Item"]["tags"] == {"L": [{"S": "z"}, {"S": "b"}]}
    assert code(ddb.update_item, TableName=t, Key=lk, UpdateExpression="SET tags[0] = :x", ConditionExpression="tags[5] = :x",
                ExpressionAttributeValues={":x": {"S": "z"}}) == "ConditionalCheckFailedException"
    ddb.delete_item(TableName=t, Key=lk)

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

    # Message attributes: boto3 verifies MD5OfMessageAttributes on send and receive.
    attrs = {"Kind": {"DataType": "String", "StringValue": "order"}, "Qty": {"DataType": "Number", "StringValue": "42"},
             "Blob": {"DataType": "Binary", "BinaryValue": b"\x00\x01"}}
    sqs.send_message(QueueUrl=q, MessageBody="with-attrs", MessageAttributes=attrs)
    m = sqs.receive_message(QueueUrl=q, MessageAttributeNames=["Kind"])["Messages"][0]
    assert list(m["MessageAttributes"]) == ["Kind"], m
    sqs.change_message_visibility(QueueUrl=q, ReceiptHandle=m["ReceiptHandle"], VisibilityTimeout=0)
    m = sqs.receive_message(QueueUrl=q, MessageAttributeNames=["All"])["Messages"][0]
    assert m["MessageAttributes"]["Blob"]["BinaryValue"] == b"\x00\x01" and m["MessageAttributes"]["Qty"]["StringValue"] == "42"
    sqs.delete_message(QueueUrl=q, ReceiptHandle=m["ReceiptHandle"])
    assert "MessageAttributes" not in sqs.receive_message(QueueUrl=q).get("Messages", [{}])[0]
    for bad in [{"AWS.x": {"DataType": "String", "StringValue": "v"}}, {"n": {"DataType": "Number", "StringValue": "x"}},
                {f"k{i}": {"DataType": "String", "StringValue": "v"} for i in range(11)}]:
        assert code(sqs.send_message, QueueUrl=q, MessageBody="x", MessageAttributes=bad) == "InvalidParameterValue", bad
    time.sleep(1.1)
    a = sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["All"])["Attributes"]
    assert a["ApproximateNumberOfMessages"] == "0", a
    sqs.delete_queue(QueueUrl=q); sqs.delete_queue(QueueUrl=dlq)
    assert q not in sqs.list_queues().get("QueueUrls", [])


def test_iam():
    iam = boto3.client("iam", **kw)
    u, b = f"alice{run}", f"iamb{run}"
    s3.create_bucket(Bucket=b)
    s3.put_object(Bucket=b, Key="public/a.txt", Body=b"ok")
    s3.put_object(Bucket=b, Key="secret/k.txt", Body=b"no")
    doc = {"Version": "2012-10-17", "Statement": [
        {"Sid": "Read", "Effect": "Allow", "Action": ["s3:GetObject", "sts:AssumeRole"], "Resource": [f"arn:aws:s3:::{b}/*", "arn:aws:iam::*:role/*"]},
        {"Sid": "NoSecrets", "Effect": "Deny", "Action": "s3:*", "Resource": f"arn:aws:s3:::{b}/secret/*"}]}
    pol = iam.create_policy(PolicyName=f"p{run}", PolicyDocument=json.dumps(doc))["Policy"]["Arn"]
    iam.create_user(UserName=u)
    assert code(iam.create_user, UserName=u) == "EntityAlreadyExists"
    iam.attach_user_policy(UserName=u, PolicyArn=pol)
    assert iam.get_policy_version(PolicyArn=pol, VersionId="v1")["PolicyVersion"]["Document"] == doc  # boto3 url-decodes
    key = iam.create_access_key(UserName=u)["AccessKey"]
    akw = dict(kw, aws_access_key_id=key["AccessKeyId"], aws_secret_access_key=key["SecretAccessKey"])
    s3a = boto3.client("s3", config=Config(s3={"addressing_style": "path"}), **akw)
    assert boto3.client("sts", **akw).get_caller_identity()["Arn"].endswith(f":user/{u}")

    assert s3a.get_object(Bucket=b, Key="public/a.txt")["Body"].read() == b"ok"
    assert code(s3a.get_object, Bucket=b, Key="secret/k.txt") == "AccessDenied"  # explicit deny
    assert code(s3a.put_object, Bucket=b, Key="public/x", Body=b"x") == "AccessDenied"  # implicit deny
    assert code(boto3.client("dynamodb", **akw).list_tables) == "AccessDeniedException"

    # Bucket policy: grants bob (no identity policy) read on one prefix; a Deny binds even the account root,
    # but root can always manage the policy itself.
    bob = f"bob{run}"
    iam.create_user(UserName=bob)
    bk = iam.create_access_key(UserName=bob)["AccessKey"]
    s3b = boto3.client("s3", config=Config(s3={"addressing_style": "path"}), **dict(kw, aws_access_key_id=bk["AccessKeyId"], aws_secret_access_key=bk["SecretAccessKey"]))
    assert code(s3b.get_object, Bucket=b, Key="public/a.txt") == "AccessDenied"
    assert code(s3.get_bucket_policy, Bucket=b) == "NoSuchBucketPolicy"
    assert code(s3.put_bucket_policy, Bucket=b, Policy=json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:*"}]})) == "MalformedPolicy"
    bp = {"Version": "2012-10-17", "Statement": [
        {"Sid": "BobReads", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::000000000000:user/{bob}"}, "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{b}/public/*"},
        {"Sid": "LockSecrets", "Effect": "Deny", "Principal": "*", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{b}/secret/*"}]}
    s3.put_bucket_policy(Bucket=b, Policy=json.dumps(bp))
    assert json.loads(s3.get_bucket_policy(Bucket=b)["Policy"]) == bp
    assert s3b.get_object(Bucket=b, Key="public/a.txt")["Body"].read() == b"ok"
    assert code(s3b.put_object, Bucket=b, Key="public/x", Body=b"x") == "AccessDenied"
    assert code(s3.get_object, Bucket=b, Key="secret/k.txt") == "AccessDenied"  # root too
    assert code(s3b.delete_bucket_policy, Bucket=b) == "AccessDenied"
    s3.delete_bucket_policy(Bucket=b)
    assert s3.get_object(Bucket=b, Key="secret/k.txt")["Body"].read() == b"no"
    assert code(s3b.get_object, Bucket=b, Key="public/a.txt") == "AccessDenied"

    # Queue policy: same rules for SQS.
    sqb = boto3.client("sqs", **dict(kw, aws_access_key_id=bk["AccessKeyId"], aws_secret_access_key=bk["SecretAccessKey"]))
    qu = sqs.create_queue(QueueName=f"qp{run}")["QueueUrl"]
    qarn = f"arn:aws:sqs:us-east-1:000000000000:qp{run}"
    assert code(sqb.send_message, QueueUrl=qu, MessageBody="x") == "AccessDenied"
    assert code(sqs.set_queue_attributes, QueueUrl=qu, Attributes={"Policy": "{not json"}) == "InvalidAttributeValue"
    qp = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::000000000000:user/{bob}"}, "Action": "sqs:SendMessage", "Resource": qarn}]}
    sqs.set_queue_attributes(QueueUrl=qu, Attributes={"Policy": json.dumps(qp)})
    assert json.loads(sqs.get_queue_attributes(QueueUrl=qu, AttributeNames=["Policy"])["Attributes"]["Policy"]) == qp
    sqb.send_message(QueueUrl=qu, MessageBody="from-bob")
    assert code(sqb.receive_message, QueueUrl=qu) == "AccessDenied"
    sqs.set_queue_attributes(QueueUrl=qu, Attributes={"Policy": ""})
    assert code(sqb.send_message, QueueUrl=qu, MessageBody="x") == "AccessDenied"
    sqs.delete_queue(QueueUrl=qu)

    # Topic policy: same rules for SNS.
    sns, snb = boto3.client("sns", **kw), boto3.client("sns", **dict(kw, aws_access_key_id=bk["AccessKeyId"], aws_secret_access_key=bk["SecretAccessKey"]))
    tp = sns.create_topic(Name=f"tp{run}")["TopicArn"]
    assert code(snb.publish, TopicArn=tp, Message="x") == "AuthorizationError"
    assert code(sns.set_topic_attributes, TopicArn=tp, AttributeName="Policy", AttributeValue="[]") == "InvalidParameter"
    sns.set_topic_attributes(TopicArn=tp, AttributeName="Policy", AttributeValue=json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::000000000000:user/{bob}"}, "Action": "sns:Publish", "Resource": tp}]}))
    snb.publish(TopicArn=tp, Message="from-bob")
    assert code(snb.subscribe, TopicArn=tp, Protocol="sqs", Endpoint=qarn) == "AuthorizationError"
    sns.set_topic_attributes(TopicArn=tp, AttributeName="Policy", AttributeValue="")
    assert "Policy" not in sns.get_topic_attributes(TopicArn=tp)["Attributes"]
    assert code(snb.publish, TopicArn=tp, Message="x") == "AuthorizationError"
    sns.delete_topic(TopicArn=tp)

    # Function policy (AddPermission): bob may invoke only while the statement exists.
    lam = boto3.client("lambda", **kw)
    lmb = boto3.client("lambda", **dict(kw, aws_access_key_id=bk["AccessKeyId"], aws_secret_access_key=bk["SecretAccessKey"]))
    fn = f"fp{run}"
    lam.create_function(FunctionName=fn, Runtime="python3.12", Role="arn:aws:iam::000000000000:role/x", Handler="app.h",
                        Code={"ZipFile": zipped({"app.py": "def h(e, c):\n    return {'ok': True}\n"})})
    assert code(lmb.invoke, FunctionName=fn) == "AccessDeniedException"
    assert code(lam.get_policy, FunctionName=fn) == "ResourceNotFoundException"
    lam.add_permission(FunctionName=fn, StatementId="bob", Action="lambda:InvokeFunction", Principal=f"arn:aws:iam::000000000000:user/{bob}")
    assert code(lam.add_permission, FunctionName=fn, StatementId="bob", Action="lambda:InvokeFunction", Principal="*") == "ResourceConflictException"
    assert json.loads(lam.get_policy(FunctionName=fn)["Policy"])["Statement"][0]["Sid"] == "bob"
    assert json.loads(lmb.invoke(FunctionName=fn)["Payload"].read()) == {"ok": True}
    assert code(lmb.remove_permission, FunctionName=fn, StatementId="bob") == "AccessDeniedException"
    lam.remove_permission(FunctionName=fn, StatementId="bob")
    assert code(lmb.invoke, FunctionName=fn) == "AccessDeniedException"
    lam.delete_function(FunctionName=fn)

    sim = iam.simulate_principal_policy(PolicySourceArn=f"arn:aws:iam::000000000000:user/{u}", ActionNames=["s3:GetObject"],
                                        ResourceArns=[f"arn:aws:s3:::{b}/public/a", f"arn:aws:s3:::{b}/secret/a", "arn:aws:s3:::other/x"])
    assert [r["EvalDecision"] for r in sim["EvaluationResults"]] == ["allowed", "explicitDeny", "implicitDeny"], sim

    # Role assumption: trust policy names alice, role grants SQS only.
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::000000000000:user/{u}"}, "Action": "sts:AssumeRole"}]}
    r = f"worker{run}"
    iam.create_role(RoleName=r, AssumeRolePolicyDocument=json.dumps(trust))
    assert iam.get_role(RoleName=r)["Role"]["AssumeRolePolicyDocument"] == trust
    iam.put_role_policy(RoleName=r, PolicyName="sqs", PolicyDocument=json.dumps({"Statement": [{"Effect": "Allow", "Action": "sqs:*", "Resource": "*"}]}))
    c = boto3.client("sts", **akw).assume_role(RoleArn=f"arn:aws:iam::000000000000:role/{r}", RoleSessionName="job1")["Credentials"]
    rkw = dict(kw, aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"], aws_session_token=c["SessionToken"])
    assert boto3.client("sts", **rkw).get_caller_identity()["Arn"] == f"arn:aws:sts::000000000000:assumed-role/{r}/job1"
    rq = boto3.client("sqs", **rkw)
    rq.delete_queue(QueueUrl=rq.create_queue(QueueName=f"rq{run}")["QueueUrl"])
    assert code(boto3.client("s3", **rkw).list_buckets) == "AccessDenied"

    iam.create_role(RoleName=f"lambda{run}", AssumeRolePolicyDocument=json.dumps(
        {"Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}))
    assert code(boto3.client("sts", **akw).assume_role, RoleArn=f"arn:aws:iam::000000000000:role/lambda{run}", RoleSessionName="xx") == "AccessDenied"

    # Cleanup, including delete conflicts.
    assert code(iam.delete_user, UserName=u) == "DeleteConflict"
    assert code(iam.delete_policy, PolicyArn=pol) == "DeleteConflict"
    iam.detach_user_policy(UserName=u, PolicyArn=pol)
    iam.delete_access_key(UserName=u, AccessKeyId=key["AccessKeyId"])
    iam.delete_user(UserName=u)
    iam.delete_access_key(UserName=bob, AccessKeyId=bk["AccessKeyId"]); iam.delete_user(UserName=bob)
    iam.delete_policy(PolicyArn=pol)
    iam.delete_role_policy(RoleName=r, PolicyName="sqs")
    iam.delete_role(RoleName=r); iam.delete_role(RoleName=f"lambda{run}")
    assert code(iam.get_user, UserName=u) == "NoSuchEntity"
    s3.delete_objects(Bucket=b, Delete={"Objects": [{"Key": "public/a.txt"}, {"Key": "secret/k.txt"}]})
    s3.delete_bucket(Bucket=b)


def test_iam_conditions():
    # Condition operators beyond String*/Bool: Numeric*, Date*, IpAddress and the ForAnyValue/ForAllValues
    # qualifiers, evaluated against the live request context (aws:SourceIp=127.0.0.1, aws:EpochTime/CurrentTime,
    # aws:RequestedRegion=us-east-1).
    iam = boto3.client("iam", **kw)
    u, b = f"cond{run}", f"condb{run}"
    s3.create_bucket(Bucket=b)
    s3.put_object(Bucket=b, Key="a.txt", Body=b"ok")
    iam.create_user(UserName=u)
    k = iam.create_access_key(UserName=u)["AccessKey"]
    ukw = dict(kw, aws_access_key_id=k["AccessKeyId"], aws_secret_access_key=k["SecretAccessKey"])
    us3 = boto3.client("s3", config=Config(s3={"addressing_style": "path"}), **ukw)

    def try_cond(cond):
        iam.put_user_policy(UserName=u, PolicyName="c", PolicyDocument=json.dumps({"Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{b}/*", "Condition": cond}]}))
        try:
            return us3.get_object(Bucket=b, Key="a.txt")["Body"].read() == b"ok"
        except ClientError:
            return False

    try:  # Numeric*: epoch time is a number in both the policy and the context
        assert try_cond({"NumericGreaterThan": {"aws:EpochTime": "1000000000"}})
        assert try_cond({"NumericLessThanEquals": {"aws:EpochTime": "9999999999"}})
        assert not try_cond({"NumericLessThan": {"aws:EpochTime": "1000000000"}})
        assert not try_cond({"NumericEquals": {"aws:EpochTime": ["1", "2"]}})
        # Date*: epoch seconds, RFC 3339 and date-only values
        assert try_cond({"DateGreaterThan": {"aws:CurrentTime": "2000-01-01T00:00:00Z"}})
        assert try_cond({"DateGreaterThanEquals": {"aws:CurrentTime": "2000-01-01"}})
        assert not try_cond({"DateLessThan": {"aws:CurrentTime": "2000-01-01T00:00:00Z"}})
        assert not try_cond({"DateGreaterThan": {"aws:CurrentTime": "9999-01-01T00:00:00Z"}})
        # IpAddress / NotIpAddress on aws:SourceIp
        assert try_cond({"IpAddress": {"aws:SourceIp": "127.0.0.1/32"}})
        assert try_cond({"IpAddress": {"aws:SourceIp": ["10.0.0.0/8", "127.0.0.0/8"]}})
        assert not try_cond({"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}})
        assert try_cond({"NotIpAddress": {"aws:SourceIp": "10.0.0.0/8"}})
        assert not try_cond({"IpAddress": {"aws:SourceIp": "::1/128"}})
        # Qualifiers: single-valued keys act like the base operator; missing keys follow AWS rules
        assert try_cond({"ForAllValues:StringEquals": {"aws:RequestedRegion": "us-east-1"}})
        assert try_cond({"ForAnyValue:StringEquals": {"aws:RequestedRegion": "us-east-1"}})
        assert not try_cond({"ForAnyValue:StringEquals": {"aws:RequestedRegion": "eu-west-1"}})
        assert try_cond({"ForAllValues:StringEquals": {"aws:MissingKey": "x"}})
        assert not try_cond({"ForAnyValue:StringEquals": {"aws:MissingKey": "x"}})
        # Unknown operators never match
        assert not try_cond({"StringSuperEquals": {"aws:RequestedRegion": "us-east-1"}})
    finally:
        iam.delete_user_policy(UserName=u, PolicyName="c")

    # The same operators work in a bucket policy (resource-based) and in SimulatePrincipalPolicy.
    bp = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::000000000000:user/{u}"}, "Action": "s3:GetObject",
                         "Resource": f"arn:aws:s3:::{b}/*", "Condition": {"IpAddress": {"aws:SourceIp": "127.0.0.0/8"}}}]}
    s3.put_bucket_policy(Bucket=b, Policy=json.dumps(bp))
    assert us3.get_object(Bucket=b, Key="a.txt")["Body"].read() == b"ok"
    bp["Statement"][0]["Condition"] = {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}
    s3.put_bucket_policy(Bucket=b, Policy=json.dumps(bp))
    assert code(us3.get_object, Bucket=b, Key="a.txt") == "AccessDenied"
    s3.delete_bucket_policy(Bucket=b)
    doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
                          "Condition": {"DateGreaterThan": {"aws:CurrentTime": "2000-01-01T00:00:00Z"}}}]}
    iam.put_user_policy(UserName=u, PolicyName="c", PolicyDocument=json.dumps(doc))
    sim = iam.simulate_principal_policy(PolicySourceArn=f"arn:aws:iam::000000000000:user/{u}", ActionNames=["s3:GetObject"], ResourceArns=["arn:aws:s3:::x/y"])
    assert sim["EvaluationResults"][0]["EvalDecision"] == "allowed"
    doc["Statement"][0]["Condition"] = {"DateLessThan": {"aws:CurrentTime": "2000-01-01T00:00:00Z"}}
    iam.put_user_policy(UserName=u, PolicyName="c", PolicyDocument=json.dumps(doc))
    sim = iam.simulate_principal_policy(PolicySourceArn=f"arn:aws:iam::000000000000:user/{u}", ActionNames=["s3:GetObject"], ResourceArns=["arn:aws:s3:::x/y"])
    assert sim["EvaluationResults"][0]["EvalDecision"] == "implicitDeny"

    iam.delete_user_policy(UserName=u, PolicyName="c")
    iam.delete_access_key(UserName=u, AccessKeyId=k["AccessKeyId"])
    iam.delete_user(UserName=u)
    s3.delete_object(Bucket=b, Key="a.txt")
    s3.delete_bucket(Bucket=b)


def test_network():
    import urllib.request
    ec2 = boto3.client("ec2", **kw)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    pub = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    priv = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.2.0/24")["Subnet"]["SubnetId"]
    assert code(ec2.create_subnet, VpcId=vpc, CidrBlock="10.0.1.128/25") == "InvalidSubnet.Conflict"
    assert code(ec2.create_subnet, VpcId=vpc, CidrBlock="10.1.0.0/24") == "InvalidSubnet.Range"
    ec2.modify_subnet_attribute(SubnetId=pub, MapPublicIpOnLaunch={"Value": True})
    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    rt = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    ec2.associate_route_table(RouteTableId=rt, SubnetId=pub)

    web = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    db = ec2.create_security_group(GroupName="db", Description="db", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=web, IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ec2.authorize_security_group_ingress(GroupId=db, IpPermissions=[{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "UserIdGroupPairs": [{"GroupId": web}]}])
    sg = ec2.describe_security_groups(GroupIds=[db])["SecurityGroups"][0]
    assert sg["IpPermissions"][0]["UserIdGroupPairs"][0]["GroupId"] == web, sg
    assert {x["GroupName"] for x in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["SecurityGroups"]} == {"default", "web", "db"}

    w = ec2.run_instances(ImageId="ami-local", MinCount=1, MaxCount=1, SubnetId=pub, SecurityGroupIds=[web])["Instances"][0]
    d = ec2.run_instances(ImageId="ami-local", MinCount=1, MaxCount=1, SubnetId=priv, SecurityGroupIds=[db])["Instances"][0]
    ec2.get_waiter("instance_running").wait(InstanceIds=[w["InstanceId"], d["InstanceId"]])
    assert w["PrivateIpAddress"] == "10.0.1.4" and "PublicIpAddress" in w and "PublicIpAddress" not in d, (w, d)

    def reach(a, b, port):
        r = json.load(urllib.request.urlopen(f"{EP}/_admin/reach?from={a}&to={b}&protocol=tcp&port={port}"))
        return r["reachable"], [h["step"] for h in r["hops"] if not h["ok"]]
    W, D = w["InstanceId"], d["InstanceId"]
    assert reach("internet", W, 443) == (True, [])
    assert reach("internet", W, 22) == (False, ["security group (inbound)"])
    assert reach("internet", D, 5432) == (False, ["route", "public IP", "security group (inbound)"])
    assert reach(W, D, 5432) == (True, [])
    assert reach(W, D, 22) == (False, ["security group (inbound)"])
    assert reach(D, "internet", 443) == (False, ["route", "public IP"])

    assert code(ec2.delete_vpc, VpcId=vpc) == "DependencyViolation"
    ec2.terminate_instances(InstanceIds=[W, D])
    for g in (web, db):
        ec2.delete_security_group(GroupId=g)
    for sn in (pub, priv):
        ec2.delete_subnet(SubnetId=sn)
    ec2.delete_route_table(RouteTableId=rt)
    ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ec2.delete_internet_gateway(InternetGatewayId=igw)
    ec2.delete_vpc(VpcId=vpc)
    assert code(ec2.describe_vpcs, VpcIds=[vpc]) == "InvalidVpcID.NotFound"



def test_sqs_fifo():
    q = sqs.create_queue(QueueName=f"orders{run}.fifo", Attributes={"FifoQueue": "true"})["QueueUrl"]
    assert code(sqs.send_message, QueueUrl=q, MessageBody="x", MessageDeduplicationId="d") == "MissingParameter"
    assert code(sqs.send_message, QueueUrl=q, MessageBody="x", MessageGroupId="g") == "InvalidParameterValue"
    a = sqs.send_message(QueueUrl=q, MessageBody="a1", MessageGroupId="A", MessageDeduplicationId="1")
    dup = sqs.send_message(QueueUrl=q, MessageBody="a1", MessageGroupId="A", MessageDeduplicationId="1")
    assert dup["MessageId"] == a["MessageId"] and dup["SequenceNumber"] == a["SequenceNumber"]
    for body, g, d in [("a2", "A", "2"), ("b1", "B", "3")]:
        sqs.send_message(QueueUrl=q, MessageBody=body, MessageGroupId=g, MessageDeduplicationId=d)
    # One message from group A in flight holds back a2; group B still flows.
    m1 = sqs.receive_message(QueueUrl=q, MaxNumberOfMessages=1, AttributeNames=["All"])["Messages"]
    assert m1[0]["Body"] == "a1" and m1[0]["Attributes"]["MessageGroupId"] == "A"
    m2 = sqs.receive_message(QueueUrl=q, MaxNumberOfMessages=10)["Messages"]
    assert [m["Body"] for m in m2] == ["b1"], m2
    sqs.delete_message(QueueUrl=q, ReceiptHandle=m1[0]["ReceiptHandle"])
    assert [m["Body"] for m in sqs.receive_message(QueueUrl=q, MaxNumberOfMessages=10)["Messages"]] == ["a2"]
    cq = sqs.create_queue(QueueName=f"cbd{run}.fifo", Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"})["QueueUrl"]
    x, y = (sqs.send_message(QueueUrl=cq, MessageBody="same", MessageGroupId="g") for _ in range(2))
    assert x["MessageId"] == y["MessageId"]
    assert code(sqs.create_queue, QueueName=f"nofifo{run}", Attributes={"FifoQueue": "true"}) == "InvalidParameterValue"


def test_sigv4():
    bad = boto3.client("dynamodb", **dict(kw, aws_secret_access_key="wrong"))
    try:
        bad.list_tables()
    except ClientError as e:
        assert e.response["Error"]["Code"] == "InvalidSignatureException", e.response
    else:
        raise Skip("VERIFY_SIGV4 off")
    s3b = boto3.client("s3", config=Config(s3={"addressing_style": "path"}), **dict(kw, aws_secret_access_key="wrong"))
    assert code(s3b.list_buckets) == "SignatureDoesNotMatch"
    import urllib.request, urllib.error
    try:
        urllib.request.urlopen(EP + "/")
        raise AssertionError("unsigned request accepted")
    except urllib.error.HTTPError as e:
        assert e.code == 403
    assert "Buckets" in s3.list_buckets()

def test_config():
    import urllib.request
    c = json.loads(urllib.request.urlopen(EP + "/_admin/config").read())
    assert c["enforce_iam"] is True and c["vars"]["ENFORCE_IAM"] == "1" and "RC_ROOT_SECRET" not in c["vars"], c


def test_sns_to_sqs():
    sns = boto3.client("sns", **kw)
    t = sns.create_topic(Name=f"orders{run}")["TopicArn"]
    assert t in [x["TopicArn"] for x in sns.list_topics()["Topics"]]
    all_q = sqs.create_queue(QueueName=f"all{run}")["QueueUrl"]
    vip_q = sqs.create_queue(QueueName=f"vip{run}")["QueueUrl"]
    arn = lambda u: sqs.get_queue_attributes(QueueUrl=u, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sns.subscribe(TopicArn=t, Protocol="sqs", Endpoint=arn(all_q))
    sns.subscribe(TopicArn=t, Protocol="sqs", Endpoint=arn(vip_q), ReturnSubscriptionArn=True,
                  Attributes={"RawMessageDelivery": "true", "FilterPolicy": json.dumps({"tier": ["gold"]})})
    assert len(sns.list_subscriptions_by_topic(TopicArn=t)["Subscriptions"]) == 2
    assert sns.get_topic_attributes(TopicArn=t)["Attributes"]["SubscriptionsConfirmed"] == "2"
    sns.publish(TopicArn=t, Message="plain", Subject="s1", MessageAttributes={"tier": {"DataType": "String", "StringValue": "silver"}})
    sns.publish(TopicArn=t, Message="golden", MessageAttributes={"tier": {"DataType": "String", "StringValue": "gold"}})
    got = [json.loads(m["Body"]) for m in sqs.receive_message(QueueUrl=all_q, MaxNumberOfMessages=10)["Messages"]]
    assert [g["Message"] for g in got] == ["plain", "golden"] and got[0]["Subject"] == "s1" and got[0]["TopicArn"] == t
    assert got[1]["MessageAttributes"]["tier"] == {"Type": "String", "Value": "gold"}
    vip = sqs.receive_message(QueueUrl=vip_q, MaxNumberOfMessages=10, MessageAttributeNames=["All"])["Messages"]
    assert [m["Body"] for m in vip] == ["golden"], vip  # filter + raw delivery
    assert vip[0]["MessageAttributes"]["tier"] == {"DataType": "String", "StringValue": "gold"}, vip  # raw keeps attributes
    assert code(sns.publish, TopicArn=t + "x", Message="m") == "NotFound"
    sns.delete_topic(TopicArn=t)
    sqs.delete_queue(QueueUrl=all_q); sqs.delete_queue(QueueUrl=vip_q)


def test_secrets_ssm_kms():
    sm = boto3.client("secretsmanager", **kw)
    n = f"db/{run}"
    arn = sm.create_secret(Name=n, SecretString='{"pw":"one"}')["ARN"]
    assert code(sm.create_secret, Name=n, SecretString="x") == "ResourceExistsException"
    assert json.loads(sm.get_secret_value(SecretId=n)["SecretString"]) == {"pw": "one"}
    sm.put_secret_value(SecretId=arn, SecretString='{"pw":"two"}')
    assert json.loads(sm.get_secret_value(SecretId=arn)["SecretString"])["pw"] == "two"
    assert json.loads(sm.get_secret_value(SecretId=n, VersionStage="AWSPREVIOUS")["SecretString"])["pw"] == "one"
    assert n in [x["Name"] for x in sm.list_secrets()["SecretList"]]
    sm.delete_secret(SecretId=n)
    assert code(sm.get_secret_value, SecretId=n) == "InvalidRequestException"
    sm.restore_secret(SecretId=n)
    sm.delete_secret(SecretId=n, ForceDeleteWithoutRecovery=True)
    assert code(sm.get_secret_value, SecretId=n) == "ResourceNotFoundException"

    ssm = boto3.client("ssm", **kw)
    base = f"/app{run}"
    ssm.put_parameter(Name=f"{base}/db/url", Value="postgres://x", Type="String")
    ssm.put_parameter(Name=f"{base}/db/pw", Value="hunter2", Type="SecureString")
    ssm.put_parameter(Name=f"{base}/flag", Value="on", Type="String")
    assert code(ssm.put_parameter, Name=f"{base}/flag", Value="off", Type="String") == "ParameterAlreadyExists"
    assert ssm.put_parameter(Name=f"{base}/flag", Value="off", Overwrite=True)["Version"] == 2
    assert ssm.get_parameter(Name=f"{base}/db/pw", WithDecryption=True)["Parameter"]["Value"] == "hunter2"
    assert ssm.get_parameter(Name=f"{base}/db/pw")["Parameter"]["Value"] != "hunter2"
    assert sorted(p["Name"] for p in ssm.get_parameters_by_path(Path=base)["Parameters"]) == [f"{base}/flag"]
    assert len(ssm.get_parameters_by_path(Path=base, Recursive=True)["Parameters"]) == 3
    r = ssm.get_parameters(Names=[f"{base}/flag", f"{base}/nope"])
    assert [p["Value"] for p in r["Parameters"]] == ["off"] and r["InvalidParameters"] == [f"{base}/nope"]
    ssm.delete_parameters(Names=[f"{base}/db/url", f"{base}/db/pw", f"{base}/flag"])
    assert code(ssm.get_parameter, Name=f"{base}/flag") == "ParameterNotFound"

    kms = boto3.client("kms", **kw)
    k = kms.create_key(Description="test")["KeyMetadata"]["KeyId"]
    kms.create_alias(AliasName=f"alias/app{run}", TargetKeyId=k)
    ct = kms.encrypt(KeyId=f"alias/app{run}", Plaintext=b"secret data", EncryptionContext={"app": "x"})["CiphertextBlob"]
    assert b"secret data" not in ct
    assert kms.decrypt(CiphertextBlob=ct, EncryptionContext={"app": "x"})["Plaintext"] == b"secret data"
    assert code(kms.decrypt, CiphertextBlob=ct, EncryptionContext={"app": "y"}) == "InvalidCiphertextException"
    dk = kms.generate_data_key(KeyId=k, KeySpec="AES_256")
    assert len(dk["Plaintext"]) == 32 and kms.decrypt(CiphertextBlob=dk["CiphertextBlob"])["Plaintext"] == dk["Plaintext"]
    kms.disable_key(KeyId=k)
    assert code(kms.encrypt, KeyId=k, Plaintext=b"x") == "DisabledException"
    kms.schedule_key_deletion(KeyId=k, PendingWindowInDays=7)
    assert kms.describe_key(KeyId=k)["KeyMetadata"]["KeyState"] == "PendingDeletion"


def test_logs():
    logs = boto3.client("logs", **kw)
    g = f"/app/{run}"
    logs.create_log_group(logGroupName=g)
    assert code(logs.create_log_group, logGroupName=g) == "ResourceAlreadyExistsException"
    logs.create_log_stream(logGroupName=g, logStreamName="s1")
    now = int(time.time() * 1000)
    logs.put_log_events(logGroupName=g, logStreamName="s1", logEvents=[
        {"timestamp": now + i, "message": m} for i, m in enumerate(["start", "ERROR db timeout user 42", "done"])])
    ev = logs.get_log_events(logGroupName=g, logStreamName="s1", startFromHead=True)
    assert [e["message"] for e in ev["events"]] == ["start", "ERROR db timeout user 42", "done"]
    again = logs.get_log_events(logGroupName=g, logStreamName="s1", nextToken=ev["nextForwardToken"])
    assert again["events"] == [] and again["nextForwardToken"] == ev["nextForwardToken"]
    f = logs.filter_log_events(logGroupName=g, filterPattern='ERROR "user 42"')
    assert [e["message"] for e in f["events"]] == ["ERROR db timeout user 42"]
    assert logs.describe_log_streams(logGroupName=g)["logStreams"][0]["logStreamName"] == "s1"
    logs.put_retention_policy(logGroupName=g, retentionInDays=7)
    assert logs.describe_log_groups(logGroupNamePrefix=g)["logGroups"][0]["retentionInDays"] == 7
    logs.delete_log_group(logGroupName=g)
    assert code(logs.get_log_events, logGroupName=g, logStreamName="s1") == "ResourceNotFoundException"


PY_FN = r"""
import base64, datetime, hashlib, hmac, json, os, time, urllib.request
def signed(method, url, body, service, headers=None):
    # Minimal SigV4 with the function's session keys (stdlib only), so VERIFY_SIGV4=1 accepts it.
    e = os.environ
    host, path = url.split("://", 1)[1].split("/", 1)
    t = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    h = {"host": host, "x-amz-date": t, "x-amz-content-sha256": hashlib.sha256(body).hexdigest(), "x-amz-security-token": e["AWS_SESSION_TOKEN"]}
    names = ";".join(sorted(h))
    creq = "\n".join([method, "/" + path, "", "".join(f"{k}:{h[k]}\n" for k in sorted(h)), names, h["x-amz-content-sha256"]])
    scope = f"{t[:8]}/us-east-1/{service}/aws4_request"
    k = ("AWS4" + e["AWS_SECRET_ACCESS_KEY"]).encode()
    for p in (t[:8], "us-east-1", service, "aws4_request"):
        k = hmac.new(k, p.encode(), hashlib.sha256).digest()
    sts = f"AWS4-HMAC-SHA256\n{t}\n{scope}\n" + hashlib.sha256(creq.encode()).hexdigest()
    h["Authorization"] = f"AWS4-HMAC-SHA256 Credential={e['AWS_ACCESS_KEY_ID']}/{scope}, SignedHeaders={names}, Signature=" + hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    del h["host"]
    return urllib.request.Request(url, data=body, method=method, headers={**h, **(headers or {})})
def handler(event, ctx):
    print("hello log", ctx.function_name)
    ep = os.environ["AWS_ENDPOINT_URL"]
    req = signed("POST", ep + "/", b"Action=GetCallerIdentity&Version=2011-06-15", "sts", {"Content-Type": "application/x-www-form-urlencoded"})
    who = urllib.request.urlopen(req).read().decode()
    for r in event.get("Records", []):
        body = r.get("body") or r.get("Sns", {}).get("Message") or base64.b64decode(r.get("kinesis", {}).get("data", "")).decode()
        urllib.request.urlopen(signed("PUT", f"{ep}/{os.environ['BUCKET']}/{body}", b"x", "s3"))
    return {"echo": event.get("x"), "who": who, "stage": os.environ.get("STAGE")}
def boom(event, ctx):
    raise ValueError("bad input")
def slow(event, ctx):
    time.sleep(3)
"""
NODE_FN = "exports.handler = async (event, ctx) => ({ doubled: event.n * 2, name: ctx.functionName });"


def zipped(files):
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, src in files.items():
            z.writestr(n, src)
    return buf.getvalue()


def test_lambda():
    lam, iam, logs, sns = (boto3.client(n, **kw) for n in ("lambda", "iam", "logs", "sns"))
    role = iam.create_role(RoleName=f"exec{run}", AssumeRolePolicyDocument=json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
    iam.put_role_policy(RoleName=f"exec{run}", PolicyName="writes", PolicyDocument=json.dumps({"Statement": [
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"}]}))
    b = f"lam{run}"
    s3.create_bucket(Bucket=b)
    fn = f"fn{run}"
    common = dict(Role=role, Code={"ZipFile": zipped({"app.py": PY_FN})}, Runtime="python3.12")
    lam.create_function(FunctionName=fn, Handler="app.handler", Environment={"Variables": {"STAGE": "dev", "BUCKET": b}}, **common)
    lam.get_waiter("function_active_v2").wait(FunctionName=fn)
    assert code(lam.create_function, FunctionName=fn, Handler="app.handler", **common) == "ResourceConflictException"

    r = lam.invoke(FunctionName=fn, Payload=json.dumps({"x": 7}), LogType="Tail")
    out = json.loads(r["Payload"].read())
    assert "FunctionError" not in r and out["echo"] == 7 and out["stage"] == "dev", out
    assert f"assumed-role/exec{run}/{fn}" in out["who"], out["who"]  # code runs as its execution role
    import base64
    assert "hello log" in base64.b64decode(r["LogResult"]).decode()
    time.sleep(0.2)
    assert any("hello log" in e["message"] for e in logs.filter_log_events(logGroupName=f"/aws/lambda/{fn}")["events"])

    lam.create_function(FunctionName=fn + "-boom", Handler="app.boom", **common)
    r = lam.invoke(FunctionName=fn + "-boom")
    err = json.loads(r["Payload"].read())
    assert r["FunctionError"] == "Unhandled" and err["errorType"] == "ValueError" and err["errorMessage"] == "bad input", err
    lam.create_function(FunctionName=fn + "-slow", Handler="app.slow", Timeout=1, **common)
    r = lam.invoke(FunctionName=fn + "-slow")
    assert r["FunctionError"] == "Unhandled" and "timed out" in json.loads(r["Payload"].read())["errorMessage"]

    lam.create_function(FunctionName=fn + "-node", Handler="index.handler", Runtime="nodejs22.x", Role=role, Code={"ZipFile": zipped({"index.js": NODE_FN})})
    assert json.loads(lam.invoke(FunctionName=fn + "-node", Payload='{"n": 21}')["Payload"].read()) == {"doubled": 42, "name": fn + "-node"}

    # SQS -> Lambda: each message body becomes an S3 key written by the function.
    q = sqs.create_queue(QueueName=f"jobs{run}")["QueueUrl"]
    qarn = sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    m = lam.create_event_source_mapping(EventSourceArn=qarn, FunctionName=fn, BatchSize=5)["UUID"]
    sqs.send_message_batch(QueueUrl=q, Entries=[{"Id": str(i), "MessageBody": f"job-{i}"} for i in range(3)])
    # SNS -> Lambda
    t = sns.create_topic(Name=f"t{run}")["TopicArn"]
    sns.subscribe(TopicArn=t, Protocol="lambda", Endpoint=lam.get_function(FunctionName=fn)["Configuration"]["FunctionArn"])
    sns.publish(TopicArn=t, Message="from-sns")
    # Kinesis -> Lambda: records written before the mapping are read from TRIM_HORIZON, per shard in order.
    kin = boto3.client("kinesis", **kw)
    kin.create_stream(StreamName=f"clicks{run}", ShardCount=2)
    sarn = kin.describe_stream_summary(StreamName=f"clicks{run}")["StreamDescriptionSummary"]["StreamARN"]
    for i in range(3):
        kin.put_record(StreamName=f"clicks{run}", Data=f"kin-{i}".encode(), PartitionKey=f"user{i}")
    assert code(lam.create_event_source_mapping, EventSourceArn=sarn, FunctionName=fn) == "InvalidParameterValueException"  # StartingPosition required
    km = lam.create_event_source_mapping(EventSourceArn=sarn, FunctionName=fn, StartingPosition="TRIM_HORIZON", BatchSize=50)
    assert km["StartingPosition"] == "TRIM_HORIZON" and km["BatchSize"] == 50
    want = {"job-0", "job-1", "job-2", "from-sns", "kin-0", "kin-1", "kin-2"}
    for _ in range(50):
        keys = {o["Key"] for o in s3.list_objects_v2(Bucket=b).get("Contents", [])}
        if want <= keys:
            break
        time.sleep(0.2)
    assert want <= keys, keys
    time.sleep(0.3)
    assert sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["All"])["Attributes"]["ApproximateNumberOfMessages"] == "0"

    # Versions and aliases: v1 is frozen with STAGE=dev; "live" moves from v1 to $LATEST.
    v1 = lam.publish_version(FunctionName=fn)
    assert v1["Version"] == "1" and v1["FunctionArn"].endswith(":1")
    assert lam.publish_version(FunctionName=fn)["Version"] == "1"  # nothing changed: same version
    lam.create_alias(FunctionName=fn, Name="live", FunctionVersion="1")
    assert code(lam.create_alias, FunctionName=fn, Name="live", FunctionVersion="1") == "ResourceConflictException"
    assert code(lam.create_alias, FunctionName=fn, Name="old", FunctionVersion="9") == "ResourceNotFoundException"
    lam.update_function_configuration(FunctionName=fn, Environment={"Variables": {"STAGE": "prod", "BUCKET": b}})
    assert json.loads(lam.invoke(FunctionName=fn, Payload="{}")["Payload"].read())["stage"] == "prod"
    r = lam.invoke(FunctionName=fn, Qualifier="live", Payload="{}")
    assert json.loads(r["Payload"].read())["stage"] == "dev" and r["ExecutedVersion"] == "1"
    assert json.loads(lam.invoke(FunctionName=f"{fn}:1", Payload="{}")["Payload"].read())["stage"] == "dev"
    assert code(lam.invoke, FunctionName=fn, Qualifier="nope") == "ResourceNotFoundException"
    assert [v["Version"] for v in lam.list_versions_by_function(FunctionName=fn)["Versions"]] == ["$LATEST", "1"]
    assert lam.get_function_configuration(FunctionName=fn, Qualifier="live")["Environment"]["Variables"]["STAGE"] == "dev"
    lam.update_alias(FunctionName=fn, Name="live", FunctionVersion="$LATEST")
    assert lam.get_alias(FunctionName=fn, Name="live")["FunctionVersion"] == "$LATEST"
    assert json.loads(lam.invoke(FunctionName=fn, Qualifier="live", Payload="{}")["Payload"].read())["stage"] == "prod"
    assert [a["Name"] for a in lam.list_aliases(FunctionName=fn)["Aliases"]] == ["live"]
    lam.delete_alias(FunctionName=fn, Name="live")
    assert code(lam.get_alias, FunctionName=fn, Name="live") == "ResourceNotFoundException"
    assert {fn, fn + "-node"} <= {f["FunctionName"] for f in lam.list_functions()["Functions"]}
    lam.delete_event_source_mapping(UUID=m); lam.delete_event_source_mapping(UUID=km["UUID"]); kin.delete_stream(StreamName=f"clicks{run}")
    for f in (fn, fn + "-boom", fn + "-slow", fn + "-node"):
        lam.delete_function(FunctionName=f)
    assert code(lam.get_function, FunctionName=fn) == "ResourceNotFoundException"
    sns.delete_topic(TopicArn=t); sqs.delete_queue(QueueUrl=q)
    s3.delete_objects(Bucket=b, Delete={"Objects": [{"Key": k} for k in keys]}); s3.delete_bucket(Bucket=b)


def test_s3_notifications():
    sns = boto3.client("sns", **kw)
    b = f"evt{run}"
    s3.create_bucket(Bucket=b)
    q1 = sqs.create_queue(QueueName=f"created{run}")["QueueUrl"]
    q2 = sqs.create_queue(QueueName=f"removed{run}")["QueueUrl"]
    arn = lambda u: sqs.get_queue_attributes(QueueUrl=u, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    t = sns.create_topic(Name=f"removed{run}")["TopicArn"]
    sns.subscribe(TopicArn=t, Protocol="sqs", Endpoint=arn(q2), Attributes={"RawMessageDelivery": "true"})
    cfg = {"QueueConfigurations": [{"Id": "csv-in", "QueueArn": arn(q1), "Events": ["s3:ObjectCreated:*"],
                                    "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": "in/"}, {"Name": "suffix", "Value": ".csv"}]}}}],
           "TopicConfigurations": [{"Id": "gone", "TopicArn": t, "Events": ["s3:ObjectRemoved:*"]}]}
    s3.put_bucket_notification_configuration(Bucket=b, NotificationConfiguration=cfg)
    got = s3.get_bucket_notification_configuration(Bucket=b)
    assert got["QueueConfigurations"][0]["QueueArn"] == arn(q1) and got["TopicConfigurations"][0]["TopicArn"] == t, got
    for k in ("in/a.csv", "in/b.txt", "other/c.csv"):
        s3.put_object(Bucket=b, Key=k, Body=b"1,2")
    s3.delete_object(Bucket=b, Key="in/a.csv")
    created = [json.loads(m["Body"])["Records"][0] for m in sqs.receive_message(QueueUrl=q1, MaxNumberOfMessages=10)["Messages"]]
    assert [(r["eventName"], r["s3"]["object"]["key"], r["s3"]["object"]["size"]) for r in created] == [("ObjectCreated:Put", "in/a.csv", 3)], created
    removed = json.loads(sqs.receive_message(QueueUrl=q2)["Messages"][0]["Body"])["Records"][0]
    assert removed["eventName"] == "ObjectRemoved:Delete" and removed["s3"]["bucket"]["name"] == b
    s3.delete_objects(Bucket=b, Delete={"Objects": [{"Key": "in/b.txt"}, {"Key": "other/c.csv"}]})
    s3.delete_bucket(Bucket=b)
    sns.delete_topic(TopicArn=t); sqs.delete_queue(QueueUrl=q1); sqs.delete_queue(QueueUrl=q2)


def test_chaos():
    import urllib.request
    def set_rules(rules):
        urllib.request.urlopen(urllib.request.Request(f"{EP}/_admin/chaos", data=json.dumps({"rules": rules}).encode(),
                                                      headers={"x-rocalcloud": "1"}, method="POST"))
    once = Config(retries={"max_attempts": 1, "mode": "standard"})
    d1 = boto3.client("dynamodb", config=once, **kw)
    q1 = boto3.client("sqs", config=once, **kw)
    try:
        set_rules([{"service": "dynamodb", "op": "List*", "throttle_rate": 1.0},
                   {"service": "sqs", "error_rate": 1.0},
                   {"service": "s3", "op": "ListBuckets", "latency_ms": 300}])
        assert code(d1.list_tables) == "ProvisionedThroughputExceededException"
        assert code(q1.list_queues) == "InternalFailure"
        t0 = time.time(); s3.list_buckets(); assert time.time() - t0 >= 0.3
        assert json.load(urllib.request.urlopen(f"{EP}/_admin/chaos"))["rules"][0]["service"] == "dynamodb"
    finally:
        set_rules([])
    d1.list_tables(); q1.list_queues()


def test_eventbridge():
    eb = boto3.client("events", **kw)
    big = sqs.create_queue(QueueName=f"bigorders{run}")["QueueUrl"]
    tick = sqs.create_queue(QueueName=f"tick{run}")["QueueUrl"]
    arn = lambda u: sqs.get_queue_attributes(QueueUrl=u, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    eb.create_event_bus(Name=f"shop{run}")
    bus = f"shop{run}"
    eb.put_rule(Name="big", EventBusName=bus, EventPattern=json.dumps({"source": ["shop"], "detail": {"total": [{"numeric": [">=", 100]}]}}))
    eb.put_targets(Rule="big", EventBusName=bus, Targets=[{"Id": "q", "Arn": arn(big), "InputPath": "$.detail"}])
    assert eb.list_targets_by_rule(Rule="big", EventBusName=bus)["Targets"][0]["Arn"] == arn(big)
    r = eb.put_events(Entries=[{"EventBusName": bus, "Source": "shop", "DetailType": "Order", "Detail": json.dumps({"id": i, "total": t})}
                               for i, t in [(1, 50), (2, 150), (3, 300)]])
    assert r["FailedEntryCount"] == 0 and len(r["Entries"]) == 3
    got = sorted(json.loads(m["Body"])["id"] for m in sqs.receive_message(QueueUrl=big, MaxNumberOfMessages=10)["Messages"])
    assert got == [2, 3], got

    # InputTransformer: values from the event into a JSON template (strings inside quotes, raw JSON outside).
    shaped = sqs.create_queue(QueueName=f"shaped{run}")["QueueUrl"]
    eb.put_rule(Name="shape", EventBusName=bus, EventPattern=json.dumps({"source": ["shop"]}))
    eb.put_targets(Rule="shape", EventBusName=bus, Targets=[{"Id": "s", "Arn": arn(shaped), "InputTransformer": {
        "InputPathsMap": {"id": "$.detail.id", "total": "$.detail.total"},
        "InputTemplate": '{"text": "order <id> = <total>", "total": <total>, "rule": "<aws.events.rule-name>"}'}}])
    assert code(eb.put_targets, Rule="shape", EventBusName=bus, Targets=[{"Id": "x", "Arn": arn(shaped), "InputTransformer": {"InputPathsMap": {"a": "detail"}, "InputTemplate": "<a>"}}]) == "ValidationException"
    eb.put_events(Entries=[{"EventBusName": bus, "Source": "shop", "DetailType": "Order", "Detail": json.dumps({"id": 7, "total": 42})}])
    body = json.loads(sqs.receive_message(QueueUrl=shaped)["Messages"][0]["Body"])
    assert body == {"text": "order 7 = 42", "total": 42, "rule": "shape"}, body
    eb.remove_targets(Rule="shape", EventBusName=bus, Ids=["s"]); eb.delete_rule(Name="shape", EventBusName=bus); sqs.delete_queue(QueueUrl=shaped)
    # cron(): accepted (UTC, one day field must be "?"), malformed ones rejected.
    eb.put_rule(Name=f"nightly{run}", ScheduleExpression="cron(0 3 ? * MON-FRI *)")
    assert eb.describe_rule(Name=f"nightly{run}")["ScheduleExpression"] == "cron(0 3 ? * MON-FRI *)"
    assert code(eb.put_rule, Name=f"bad{run}", ScheduleExpression="cron(0 3 * * * *)") == "ValidationException"
    eb.delete_rule(Name=f"nightly{run}")

    eb.put_rule(Name=f"every{run}", ScheduleExpression="rate(1 second)")
    eb.put_targets(Rule=f"every{run}", Targets=[{"Id": "t", "Arn": arn(tick)}])
    time.sleep(2.5)
    ticks = sqs.receive_message(QueueUrl=tick, MaxNumberOfMessages=10).get("Messages", [])
    assert ticks and json.loads(ticks[0]["Body"])["detail-type"] == "Scheduled Event", ticks
    eb.disable_rule(Name=f"every{run}")
    assert eb.describe_rule(Name=f"every{run}")["State"] == "DISABLED"
    assert code(eb.delete_rule, Name=f"every{run}") == "ValidationException"  # still has targets
    eb.remove_targets(Rule=f"every{run}", Ids=["t"]); eb.delete_rule(Name=f"every{run}")
    eb.remove_targets(Rule="big", EventBusName=bus, Ids=["q"]); eb.delete_rule(Name="big", EventBusName=bus)
    eb.delete_event_bus(Name=bus)
    sqs.delete_queue(QueueUrl=big); sqs.delete_queue(QueueUrl=tick)


SFN_FN = """
def price(event, ctx):
    return {"total": event["qty"] * 10}
def flaky(event, ctx):
    raise ValueError("upstream down")
"""


def test_step_functions():
    sf, lam = boto3.client("stepfunctions", **kw), boto3.client("lambda", **kw)
    lam.create_function(FunctionName=f"price{run}", Runtime="python3.12", Role="arn:aws:iam::000000000000:role/x", Handler="app.price", Code={"ZipFile": zipped({"app.py": SFN_FN})})
    lam.create_function(FunctionName=f"flaky{run}", Runtime="python3.12", Role="arn:aws:iam::000000000000:role/x", Handler="app.flaky", Code={"ZipFile": zipped({"app.py": SFN_FN})})
    t = f"orders{run}"
    ddb.create_table(TableName=t, BillingMode="PAY_PER_REQUEST", KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                     AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}])
    q = sqs.create_queue(QueueName=f"ship{run}")["QueueUrl"]
    order = {
        "StartAt": "Prepare",
        "States": {
            "Prepare": {"Type": "Pass", "Parameters": {"id.$": "$.id", "qty.$": "$.qty", "items.$": "$.items", "label.$": "States.Format('order-{}', $.id)"}, "Next": "Price"},
            "Price": {"Type": "Task", "Resource": "arn:aws:states:::lambda:invoke",
                      "Parameters": {"FunctionName": f"price{run}", "Payload": {"qty.$": "$.qty"}},
                      "ResultSelector": {"total.$": "$.Payload.total"}, "ResultPath": "$.price", "Next": "Big?"},
            "Big?": {"Type": "Choice", "Choices": [{"Variable": "$.price.total", "NumericGreaterThanEquals": 100, "Next": "Fulfil"}], "Default": "TooSmall"},
            "TooSmall": {"Type": "Fail", "Error": "Order.TooSmall", "Cause": "minimum is 100"},
            "Fulfil": {"Type": "Parallel", "ResultPath": None, "Next": "EachItem", "Branches": [
                {"StartAt": "Ship", "States": {"Ship": {"Type": "Task", "Resource": "arn:aws:states:::sqs:sendMessage",
                                                         "Parameters": {"QueueUrl": q, "MessageBody.$": "$.label"}, "End": True}}},
                {"StartAt": "Save", "States": {"Save": {"Type": "Task", "Resource": "arn:aws:states:::dynamodb:putItem",
                                                         "Parameters": {"TableName": t, "Item": {"id": {"S.$": "$.id"}}}, "End": True}}}]},
            "EachItem": {"Type": "Map", "ItemsPath": "$.items", "ResultPath": "$.lines",
                         "ItemSelector": {"sku.$": "$$.Map.Item.Value", "n.$": "$$.Map.Item.Index"},
                         "ItemProcessor": {"StartAt": "Line", "States": {"Line": {"Type": "Pass", "End": True}}}, "Next": "Done"},
            "Done": {"Type": "Succeed"},
        },
    }
    sm = sf.create_state_machine(name=f"order{run}", definition=json.dumps(order), roleArn="arn:aws:iam::000000000000:role/x")["stateMachineArn"]

    def finish(arn):
        for _ in range(100):
            d = sf.describe_execution(executionArn=arn)
            if d["status"] != "RUNNING":
                return d
            time.sleep(0.1)
        raise AssertionError("execution did not finish")

    ok = finish(sf.start_execution(stateMachineArn=sm, name="big", input=json.dumps({"id": "o1", "qty": 12, "items": ["a", "b"]}))["executionArn"])
    assert ok["status"] == "SUCCEEDED", ok
    out = json.loads(ok["output"])
    assert out["price"] == {"total": 120} and out["label"] == "order-o1" and out["lines"] == [{"sku": "a", "n": 0}, {"sku": "b", "n": 1}], out
    assert sqs.receive_message(QueueUrl=q)["Messages"][0]["Body"] == "order-o1"
    assert ddb.get_item(TableName=t, Key={"id": {"S": "o1"}})["Item"]["id"] == {"S": "o1"}
    small = finish(sf.start_execution(stateMachineArn=sm, input=json.dumps({"id": "o2", "qty": 1, "items": []}))["executionArn"])
    assert (small["status"], small["error"]) == ("FAILED", "Order.TooSmall"), small
    assert len(sf.list_executions(stateMachineArn=sm)["executions"]) == 2
    assert code(sf.start_execution, stateMachineArn=sm, name="big", input="{}") == "ExecutionAlreadyExists"

    recover = {"StartAt": "Call", "States": {
        "Call": {"Type": "Task", "Resource": lam.get_function(FunctionName=f"flaky{run}")["Configuration"]["FunctionArn"],
                 "Retry": [{"ErrorEquals": ["ValueError"], "MaxAttempts": 1, "IntervalSeconds": 1}],
                 "Catch": [{"ErrorEquals": ["States.ALL"], "ResultPath": "$.failure", "Next": "Recovered"}], "End": True},
        "Recovered": {"Type": "Pass", "End": True}}}
    sm2 = sf.create_state_machine(name=f"recover{run}", definition=json.dumps(recover), roleArn="arn:aws:iam::000000000000:role/x")["stateMachineArn"]
    r = finish(sf.start_execution(stateMachineArn=sm2, input='{"x": 1}')["executionArn"])
    assert r["status"] == "SUCCEEDED" and json.loads(r["output"])["failure"]["Error"] == "ValueError", r
    hist = [e["type"] for e in sf.get_execution_history(executionArn=r["executionArn"])["events"]]
    assert hist.count("TaskRetry") == 1 and hist[0] == "ExecutionStarted" and hist[-1] == "ExecutionSucceeded", hist

    sm3 = sf.create_state_machine(name=f"wait{run}", roleArn="arn:aws:iam::000000000000:role/x",
                                  definition=json.dumps({"StartAt": "W", "States": {"W": {"Type": "Wait", "Seconds": 30, "End": True}}}))["stateMachineArn"]
    e = sf.start_execution(stateMachineArn=sm3)["executionArn"]
    sf.stop_execution(executionArn=e, error="Manual")
    assert sf.describe_execution(executionArn=e)["status"] == "ABORTED"
    # Parallel branches and Map items run concurrently: three 1 s waits finish in about 1 s, and MaxConcurrency=1 serialises.
    w1 = {"StartAt": "W", "States": {"W": {"Type": "Wait", "Seconds": 1, "End": True}}}
    conc = {"StartAt": "P", "States": {
        "P": {"Type": "Parallel", "Branches": [w1, w1, w1], "Next": "M"},
        "M": {"Type": "Map", "ItemsPath": "$", "ItemProcessor": w1, "End": True}}}
    serial = {"StartAt": "M", "States": {"M": {"Type": "Map", "ItemsPath": "$", "MaxConcurrency": 1, "ItemProcessor": w1, "End": True}}}
    sm4 = sf.create_state_machine(name=f"conc{run}", definition=json.dumps(conc), roleArn="arn:aws:iam::000000000000:role/x")["stateMachineArn"]
    sm5 = sf.create_state_machine(name=f"serial{run}", definition=json.dumps(serial), roleArn="arn:aws:iam::000000000000:role/x")["stateMachineArn"]
    t0 = time.time(); c = finish(sf.start_execution(stateMachineArn=sm4)["executionArn"]); took = time.time() - t0
    assert c["status"] == "SUCCEEDED" and len(json.loads(c["output"])) == 3 and took < 4, (c, took)  # serial would take 6 s
    t0 = time.time(); s = finish(sf.start_execution(stateMachineArn=sm5, input='[1, 2]')["executionArn"])
    assert s["status"] == "SUCCEEDED" and time.time() - t0 >= 2, s
    # A failing branch stops its siblings: the 30 s wait is abandoned and the execution fails quickly.
    stop = {"StartAt": "P", "States": {"P": {"Type": "Parallel", "End": True, "Branches": [
        {"StartAt": "Boom", "States": {"Boom": {"Type": "Fail", "Error": "Branch.Failed"}}},
        {"StartAt": "Slow", "States": {"Slow": {"Type": "Wait", "Seconds": 30, "End": True}}}]}}}
    sm6 = sf.create_state_machine(name=f"stop{run}", definition=json.dumps(stop), roleArn="arn:aws:iam::000000000000:role/x")["stateMachineArn"]
    t0 = time.time(); f6 = finish(sf.start_execution(stateMachineArn=sm6)["executionArn"])
    assert (f6["status"], f6["error"]) == ("FAILED", "Branch.Failed") and time.time() - t0 < 5, f6
    for m in (sm, sm2, sm3, sm4, sm5, sm6):
        sf.delete_state_machine(stateMachineArn=m)
    for f in ("price", "flaky"):
        lam.delete_function(FunctionName=f"{f}{run}")
    ddb.delete_table(TableName=t); sqs.delete_queue(QueueUrl=q)


API_FN = """
import json
def handler(event, ctx):
    if event["rawPath"] == "/teapot":
        return {"statusCode": 418, "headers": {"x-kind": "tea"}, "body": "short and stout"}
    return {"route": event["routeKey"], "params": event.get("pathParameters"), "q": event.get("queryStringParameters"),
            "body": json.loads(event["body"]) if event.get("body") else None, "method": event["requestContext"]["http"]["method"]}
"""


def test_api_gateway():
    import urllib.request, urllib.error
    gw, lam = boto3.client("apigatewayv2", **kw), boto3.client("lambda", **kw)
    farn = lam.create_function(FunctionName=f"api{run}", Runtime="python3.12", Role="arn:aws:iam::000000000000:role/x",
                               Handler="app.handler", Code={"ZipFile": zipped({"app.py": API_FN})})["FunctionArn"]
    # Quick create: one $default route to the function.
    quick = gw.create_api(Name=f"quick{run}", ProtocolType="HTTP", Target=farn)
    assert json.load(urllib.request.urlopen(quick["ApiEndpoint"] + "/anything"))["route"] == "$default"

    api = gw.create_api(Name=f"shop{run}", ProtocolType="HTTP")["ApiId"]
    integ = gw.create_integration(ApiId=api, IntegrationType="AWS_PROXY", IntegrationUri=farn, PayloadFormatVersion="2.0")["IntegrationId"]
    for key in ("GET /items/{id}", "POST /items", "ANY /files/{path+}", "GET /teapot"):
        gw.create_route(ApiId=api, RouteKey=key, Target=f"integrations/{integ}")
    gw.create_stage(ApiId=api, StageName="prod", AutoDeploy=True)
    assert code(gw.create_route, ApiId=api, RouteKey="POST /items", Target=f"integrations/{integ}") == "ConflictException"
    base = gw.get_api(ApiId=api)["ApiEndpoint"] + "/prod"
    r = json.load(urllib.request.urlopen(base + "/items/42?color=red"))
    assert r == {"route": "GET /items/{id}", "params": {"id": "42"}, "q": {"color": "red"}, "body": None, "method": "GET"}, r
    req = urllib.request.Request(base + "/items", data=json.dumps({"name": "pen"}).encode(), method="POST", headers={"content-type": "application/json"})
    assert json.load(urllib.request.urlopen(req))["body"] == {"name": "pen"}
    assert json.load(urllib.request.urlopen(base + "/files/a/b.txt"))["params"] == {"path": "a/b.txt"}
    try:
        urllib.request.urlopen(base + "/teapot"); raise AssertionError
    except urllib.error.HTTPError as e:
        assert (e.code, e.headers["x-kind"], e.read()) == (418, "tea", b"short and stout")
    try:
        urllib.request.urlopen(base + "/nope"); raise AssertionError
    except urllib.error.HTTPError as e:
        assert e.code == 404
    assert len(gw.get_routes(ApiId=api)["Items"]) == 4
    gw.delete_api(ApiId=api); gw.delete_api(ApiId=quick["ApiId"])
    assert code(gw.get_api, ApiId=api) == "NotFoundException"
    lam.delete_function(FunctionName=f"api{run}")


def test_cognito():
    import base64, hashlib, hmac, urllib.request
    import jwt  # pyjwt[crypto]
    idp = boto3.client("cognito-idp", **kw)
    pool = idp.create_user_pool(PoolName=f"users{run}", UsernameAttributes=["email"], AutoVerifiedAttributes=["email"])["UserPool"]["Id"]
    cid = idp.create_user_pool_client(UserPoolId=pool, ClientName="web", ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH"])["UserPoolClient"]["ClientId"]
    email = f"kim{run}@example.com"
    assert code(idp.sign_up, ClientId=cid, Username=email, Password="weak") == "InvalidPasswordException"
    assert idp.sign_up(ClientId=cid, Username=email, Password="Str0ng!pass", UserAttributes=[{"Name": "name", "Value": "Kim"}])["UserConfirmed"] is False
    auth = lambda pw: idp.initiate_auth(ClientId=cid, AuthFlow="USER_PASSWORD_AUTH", AuthParameters={"USERNAME": email, "PASSWORD": pw})
    assert code(auth, "Str0ng!pass") == "UserNotConfirmedException"
    # The emailed code is visible to admins (GUI / event stream) instead.
    st = json.load(urllib.request.urlopen(f"{EP}/_admin/state"))
    sent = next(p for p in st["cognito"] if p["name"] == f"users{run}")["rows"][0][3]
    assert code(idp.confirm_sign_up, ClientId=cid, Username=email, ConfirmationCode="000000" if sent != "000000" else "111111") == "CodeMismatchException"
    idp.confirm_sign_up(ClientId=cid, Username=email, ConfirmationCode=sent)
    assert code(auth, "wrong") == "NotAuthorizedException"
    tok = auth("Str0ng!pass")["AuthenticationResult"]

    iss = f"{EP}/_cognito/{pool}"
    disco = json.load(urllib.request.urlopen(iss + "/.well-known/openid-configuration"))
    key = jwt.PyJWKClient(disco["jwks_uri"]).get_signing_key_from_jwt(tok["IdToken"])
    claims = jwt.decode(tok["IdToken"], key.key, algorithms=["RS256"], audience=cid, issuer=iss)
    assert claims["email"] == email and claims["name"] == "Kim" and claims["token_use"] == "id" and claims["email_verified"] is True, claims
    attrs = {a["Name"]: a["Value"] for a in idp.get_user(AccessToken=tok["AccessToken"])["UserAttributes"]}
    assert attrs["email"] == email
    again = idp.initiate_auth(ClientId=cid, AuthFlow="REFRESH_TOKEN_AUTH", AuthParameters={"REFRESH_TOKEN": tok["RefreshToken"]})
    assert "IdToken" in again["AuthenticationResult"] and "RefreshToken" not in again["AuthenticationResult"]

    # Admin-created user must set a new password first.
    idp.admin_create_user(UserPoolId=pool, Username=f"lee{run}@example.com", TemporaryPassword="Temp0rary!")
    ch = idp.initiate_auth(ClientId=cid, AuthFlow="USER_PASSWORD_AUTH", AuthParameters={"USERNAME": f"lee{run}@example.com", "PASSWORD": "Temp0rary!"})
    assert ch["ChallengeName"] == "NEW_PASSWORD_REQUIRED"
    done = idp.respond_to_auth_challenge(ClientId=cid, ChallengeName="NEW_PASSWORD_REQUIRED", Session=ch["Session"],
                                         ChallengeResponses={"USERNAME": f"lee{run}@example.com", "NEW_PASSWORD": "N3w!password"})
    assert "AccessToken" in done["AuthenticationResult"]
    assert len(idp.list_users(UserPoolId=pool)["Users"]) == 2

    sec = idp.create_user_pool_client(UserPoolId=pool, ClientName="server", GenerateSecret=True)["UserPoolClient"]
    params = {"USERNAME": email, "PASSWORD": "Str0ng!pass"}
    assert code(idp.initiate_auth, ClientId=sec["ClientId"], AuthFlow="USER_PASSWORD_AUTH", AuthParameters=params) == "NotAuthorizedException"
    params["SECRET_HASH"] = base64.b64encode(hmac.new(sec["ClientSecret"].encode(), (email + sec["ClientId"]).encode(), hashlib.sha256).digest()).decode()
    assert "IdToken" in idp.initiate_auth(ClientId=sec["ClientId"], AuthFlow="USER_PASSWORD_AUTH", AuthParameters=params)["AuthenticationResult"]
    idp.delete_user_pool(UserPoolId=pool)
    assert code(idp.get_user, AccessToken=tok["AccessToken"]) == "NotAuthorizedException"


def test_kinesis():
    k = boto3.client("kinesis", **kw)
    n = f"clicks{run}"
    k.create_stream(StreamName=n, ShardCount=2)
    k.get_waiter("stream_exists").wait(StreamName=n)
    assert code(k.create_stream, StreamName=n, ShardCount=1) == "ResourceInUseException"
    shards = [s["ShardId"] for s in k.list_shards(StreamName=n)["Shards"]]
    assert len(shards) == 2
    first = k.put_record(StreamName=n, Data=b"hello", PartitionKey="user-1")
    r = k.put_records(StreamName=n, Records=[{"Data": f"e{i}".encode(), "PartitionKey": f"user-{i % 5}"} for i in range(20)])
    assert r["FailedRecordCount"] == 0
    got = {}
    for sid in shards:
        it = k.get_shard_iterator(StreamName=n, ShardId=sid, ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
        recs = k.get_records(ShardIterator=it, Limit=100)
        got[sid] = [x["Data"] for x in recs["Records"]]
        assert k.get_records(ShardIterator=recs["NextShardIterator"])["Records"] == []
    assert sum(len(v) for v in got.values()) == 21 and all(got.values()), "records spread over both shards"
    same = [s for s, v in got.items() if b"hello" in v][0]
    it = k.get_shard_iterator(StreamName=n, ShardId=first["ShardId"], ShardIteratorType="AFTER_SEQUENCE_NUMBER",
                              StartingSequenceNumber=first["SequenceNumber"])["ShardIterator"]
    assert b"hello" not in [x["Data"] for x in k.get_records(ShardIterator=it)["Records"]] and same == first["ShardId"]
    k.delete_stream(StreamName=n)
    assert code(k.describe_stream, StreamName=n) == "ResourceNotFoundException"


def test_ses():
    import urllib.request
    v1, v2 = boto3.client("ses", **kw), boto3.client("sesv2", **kw)
    sender = f"noreply{run}@example.com"
    msg = {"Subject": {"Data": "Welcome"}, "Body": {"Text": {"Data": "Hi there"}}}
    assert code(v1.send_email, Source=sender, Destination={"ToAddresses": ["a@x.com"]}, Message=msg) == "MessageRejected"
    v1.verify_email_identity(EmailAddress=sender)
    assert sender in v1.list_identities()["Identities"]
    assert v1.get_identity_verification_attributes(Identities=[sender])["VerificationAttributes"][sender]["VerificationStatus"] == "Success"
    assert v1.send_email(Source=sender, Destination={"ToAddresses": ["a@x.com"]}, Message=msg)["MessageId"]
    v2.create_email_identity(EmailIdentity=f"shop{run}.example")
    v2.send_email(FromEmailAddress=f"orders@shop{run}.example", Destination={"ToAddresses": ["b@x.com"]},
                  Content={"Simple": {"Subject": {"Data": "Receipt"}, "Body": {"Html": {"Data": "<b>paid</b>"}}}})
    raw = f"From: {sender}\r\nTo: c@x.com\r\nSubject: Raw one\r\n\r\nraw body".encode()
    v1.send_raw_email(RawMessage={"Data": raw})
    box = json.load(urllib.request.urlopen(f"{EP}/_admin/state"))["ses"][0]["rows"]
    mine = [(r[2], r[3]) for r in box if run in r[1]]
    assert ("c@x.com", "Raw one") in mine and ("b@x.com", "Receipt") in mine and ("a@x.com", "Welcome") in mine, mine


def test_rds_elasticache():
    import shutil, subprocess
    if not shutil.which("docker") or subprocess.run(["docker", "ps"], capture_output=True).returncode != 0:
        raise Skip("no docker")
    import pg8000.native, pymysql, redis
    rds, ec = boto3.client("rds", **kw), boto3.client("elasticache", **kw)
    pg, my, rc = f"pg{run}", f"my{run}", f"rc{run}"
    rds.create_db_instance(DBInstanceIdentifier=pg, Engine="postgres", DBInstanceClass="db.t3.micro", MasterUsername="app",
                           MasterUserPassword="secret123", DBName="shop", AllocatedStorage=20)
    rds.create_db_instance(DBInstanceIdentifier=my, Engine="mysql", DBInstanceClass="db.t3.micro", MasterUsername="app",
                           MasterUserPassword="secret123", DBName="shop", AllocatedStorage=20)
    ec.create_cache_cluster(CacheClusterId=rc, Engine="redis", CacheNodeType="cache.t3.micro", NumCacheNodes=1)
    assert code(rds.create_db_instance, DBInstanceIdentifier=pg, Engine="postgres", MasterUsername="a", MasterUserPassword="secret123",
                DBInstanceClass="db.t3.micro", AllocatedStorage=20) == "DBInstanceAlreadyExists"

    def until(fn, what, secs=120):
        for _ in range(secs * 2):
            v = fn()
            if v:
                return v
            time.sleep(0.5)
        raise AssertionError(f"{what} never became available")
    db = lambda i: rds.describe_db_instances(DBInstanceIdentifier=i)["DBInstances"][0]
    p = until(lambda: (d := db(pg))["DBInstanceStatus"] == "available" and d, "postgres")
    c = pg8000.native.Connection("app", host=p["Endpoint"]["Address"], port=p["Endpoint"]["Port"], password="secret123", database="shop")
    c.run("create table t (n int)"); c.run("insert into t values (41), (1)")
    assert c.run("select sum(n) from t") == [[42]]
    c.close()
    cc = until(lambda: (x := ec.describe_cache_clusters(CacheClusterId=rc, ShowCacheNodeInfo=True)["CacheClusters"][0])["CacheClusterStatus"] == "available" and x, "redis")
    ep = cc["CacheNodes"][0]["Endpoint"]
    r = redis.Redis(host=ep["Address"], port=ep["Port"])
    r.set("k", "v"); assert r.get("k") == b"v"
    m = until(lambda: (d := db(my))["DBInstanceStatus"] == "available" and d, "mysql", 180)
    conn = pymysql.connect(host=m["Endpoint"]["Address"], port=m["Endpoint"]["Port"], user="app", password="secret123", database="shop")
    with conn.cursor() as cur:
        cur.execute("select 6 * 7"); assert cur.fetchone() == (42,)
    conn.close()

    rds.stop_db_instance(DBInstanceIdentifier=pg)
    until(lambda: db(pg)["DBInstanceStatus"] == "stopped", "stopped", 30)
    for i in (pg, my):
        rds.delete_db_instance(DBInstanceIdentifier=i, SkipFinalSnapshot=True)
    ec.delete_cache_cluster(CacheClusterId=rc)
    assert code(rds.describe_db_instances, DBInstanceIdentifier=pg) == "DBInstanceNotFound"
    time.sleep(3)
    left = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True).stdout
    assert run not in left, left


def test_ecs_alb():
    import shutil, socket, subprocess, urllib.request, urllib.error
    if not shutil.which("docker") or subprocess.run(["docker", "ps"], capture_output=True).returncode != 0:
        raise Skip("no docker")
    ecs, elb, logs = boto3.client("ecs", **kw), boto3.client("elbv2", **kw), boto3.client("logs", **kw)
    cl = f"c{run}"
    ecs.create_cluster(clusterName=cl)
    web = ecs.register_task_definition(family=f"web{run}", containerDefinitions=[{
        "name": "web", "image": "busybox", "essential": True, "portMappings": [{"containerPort": 8080}],
        "command": ["sh", "-c", "mkdir /www && hostname > /www/index.html && httpd -f -p 8080 -h /www"]}])["taskDefinition"]["taskDefinitionArn"]
    job = ecs.register_task_definition(family=f"job{run}", containerDefinitions=[{
        "name": "job", "image": "busybox", "command": ["sh", "-c", "echo hello from task; echo $GREETING; exit 3"],
        "environment": [{"name": "GREETING", "value": "env works"}],
        "logConfiguration": {"logDriver": "awslogs", "options": {"awslogs-group": f"/ecs/job{run}", "awslogs-stream-prefix": "job"}}}])["taskDefinition"]
    assert job["revision"] == 1

    def until(fn, what, secs=90):
        for _ in range(secs * 2):
            v = fn()
            if v:
                return v
            time.sleep(0.5)
        raise AssertionError(f"timed out waiting for {what}")
    t = ecs.run_task(cluster=cl, taskDefinition=f"job{run}")["tasks"][0]["taskArn"]
    done = until(lambda: (x := ecs.describe_tasks(cluster=cl, tasks=[t])["tasks"][0])["lastStatus"] == "STOPPED" and x, "batch task")
    assert done["containers"][0]["exitCode"] == 3 and "Essential container" in done["stoppedReason"], done
    msgs = [e["message"] for e in logs.filter_log_events(logGroupName=f"/ecs/job{run}")["events"]]
    assert msgs == ["hello from task", "env works"], msgs

    lb = elb.create_load_balancer(Name=f"lb{run}", Subnets=["subnet-a", "subnet-b"])["LoadBalancers"][0]["LoadBalancerArn"]
    tg = elb.create_target_group(Name=f"tg{run}", Protocol="HTTP", Port=8080, VpcId="vpc-local", TargetType="ip")["TargetGroups"][0]["TargetGroupArn"]
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0)); port = sk.getsockname()[1]
    elb.create_listener(LoadBalancerArn=lb, Protocol="HTTP", Port=port, DefaultActions=[{"Type": "forward", "TargetGroupArn": tg}])
    ecs.create_service(cluster=cl, serviceName="web", taskDefinition=web, desiredCount=2,
                       loadBalancers=[{"targetGroupArn": tg, "containerName": "web", "containerPort": 8080}])
    until(lambda: ecs.describe_services(cluster=cl, services=["web"])["services"][0]["runningCount"] == 2, "2 running tasks")
    until(lambda: [h["TargetHealth"]["State"] for h in elb.describe_target_health(TargetGroupArn=tg)["TargetHealthDescriptions"]] == ["healthy"] * 2, "healthy targets")
    seen = {urllib.request.urlopen(f"http://127.0.0.1:{port}/").read().strip() for _ in range(6)}
    assert len(seen) == 2, seen  # round-robin over both tasks

    first = ecs.list_tasks(cluster=cl, serviceName="web")["taskArns"]
    ecs.stop_task(cluster=cl, task=first[0], reason="chaos")
    until(lambda: (a := ecs.list_tasks(cluster=cl, serviceName="web")["taskArns"]) and len(a) == 2 and first[0] not in a, "replacement task")

    fixed = elb.create_listener(LoadBalancerArn=lb, Protocol="HTTP", Port=port + 1 if port < 65535 else port - 1,
                                DefaultActions=[{"Type": "fixed-response", "FixedResponseConfig": {"StatusCode": "404", "MessageBody": "nothing here"}}])["Listeners"][0]
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{fixed['Port']}/x"); raise AssertionError
    except urllib.error.HTTPError as e:
        assert (e.code, e.read()) == (404, b"nothing here")

    ecs.update_service(cluster=cl, service="web", desiredCount=0)
    ecs.delete_service(cluster=cl, service="web")
    until(lambda: not ecs.list_services(cluster=cl)["serviceArns"], "service deletion")
    elb.delete_load_balancer(LoadBalancerArn=lb)
    elb.delete_target_group(TargetGroupArn=tg)
    ecs.delete_cluster(cluster=cl)
    left = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True).stdout
    assert "rocalcloud-ecs" not in left, left


def test_service_principal_policy():
    """SNS delivery to SQS is checked against the queue policy as sns.amazonaws.com, with aws:SourceArn."""
    sns = boto3.client("sns", **kw)
    t = sns.create_topic(Name=f"gate{run}")["TopicArn"]
    other = sns.create_topic(Name=f"gate2{run}")["TopicArn"]
    u = sqs.create_queue(QueueName=f"gate{run}")["QueueUrl"]
    qa = sqs.get_queue_attributes(QueueUrl=u, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    for topic in (t, other):
        sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=qa, Attributes={"RawMessageDelivery": "true"})
    pol = lambda effect: json.dumps({"Statement": [{"Effect": effect, "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage",
                                                    "Resource": qa, "Condition": {"ArnEquals": {"aws:SourceArn": t}}}]})
    recv = lambda: [m["Body"] for m in sqs.receive_message(QueueUrl=u, MaxNumberOfMessages=10).get("Messages", [])]
    sns.publish(TopicArn=t, Message="open")  # no queue policy: accepted (lenient)
    assert recv() == ["open"]
    sqs.set_queue_attributes(QueueUrl=u, Attributes={"Policy": pol("Allow")})
    sns.publish(TopicArn=t, Message="allowed"); sns.publish(TopicArn=other, Message="wrong source")
    assert recv() == ["allowed"]
    sqs.set_queue_attributes(QueueUrl=u, Attributes={"Policy": pol("Deny")})
    sns.publish(TopicArn=t, Message="denied")
    assert recv() == []
    sqs.delete_queue(QueueUrl=u); sns.delete_topic(TopicArn=t); sns.delete_topic(TopicArn=other)


def test_strict_delivery():
    """STRICT_DELIVERY=1: SNS/EventBridge deliveries to a target with no resource policy are refused (AWS behavior).
    Spawns a second emulator on 127.0.0.1:4567; skipped when the release binary is not built."""
    import subprocess, urllib.request
    exe = "core/target/release/rocalcloud"
    if not os.path.exists(exe):
        raise Skip("release binary not built")
    env = dict(os.environ, ENFORCE_IAM="1", STRICT_DELIVERY="1", BIND="127.0.0.1:4567", RC_DNS_PORT="10531")
    p = subprocess.Popen([exe], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        ep = "http://127.0.0.1:4567"
        for _ in range(50):
            try:
                urllib.request.urlopen(f"{ep}/_admin/state", timeout=1)
                break
            except Exception:
                time.sleep(0.1)
        else:
            raise AssertionError("second emulator did not start")
        cfg = json.load(urllib.request.urlopen(f"{ep}/_admin/config"))
        assert cfg["strict_delivery"] is True and cfg["enforce_iam"] is True, cfg
        tkw = dict(kw, endpoint_url=ep)
        sns, tsqs, eb = boto3.client("sns", **tkw), boto3.client("sqs", **tkw), boto3.client("events", **tkw)
        t = sns.create_topic(Name=f"st{run}")["TopicArn"]
        u = tsqs.create_queue(QueueName=f"st{run}")["QueueUrl"]
        qa = tsqs.get_queue_attributes(QueueUrl=u, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        sns.subscribe(TopicArn=t, Protocol="sqs", Endpoint=qa, Attributes={"RawMessageDelivery": "true"})
        eb.put_rule(Name=f"st{run}", EventPattern=json.dumps({"source": ["demo"]}))
        eb.put_targets(Rule=f"st{run}", Targets=[{"Id": "q", "Arn": qa}])
        recv = lambda: [m["Body"] for m in tsqs.receive_message(QueueUrl=u, MaxNumberOfMessages=10).get("Messages", [])]
        # No queue policy: both deliveries are refused under STRICT_DELIVERY=1.
        sns.publish(TopicArn=t, Message="nope")
        eb.put_events(Entries=[{"Source": "demo", "DetailType": "x", "Detail": "{}"}])
        time.sleep(0.4)
        assert recv() == []
        # A policy granting the service principal lets them through again.
        tsqs.set_queue_attributes(QueueUrl=u, Attributes={"Policy": json.dumps({"Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": qa,
             "Condition": {"ArnEquals": {"aws:SourceArn": t}}},
            {"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": qa}]})})
        sns.publish(TopicArn=t, Message="ok")
        eb.put_events(Entries=[{"Source": "demo", "DetailType": "x", "Detail": "{}"}])
        time.sleep(0.4)
        got = recv()
        assert len(got) == 2, got
        assert "ok" in got and any("demo" in m for m in got), got  # SNS raw + EventBridge envelope
        tsqs.delete_queue(QueueUrl=u); sns.delete_topic(TopicArn=t)
    finally:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait()


def test_alb_rules():
    """Listener rules route by path and Host to different target groups (real local HTTP servers as targets)."""
    import http.server, socket, threading, urllib.request
    def server(tag):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                b = tag.encode(); self.send_response(200); self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)
            def log_message(self, *a): pass
        H.protocol_version = "HTTP/1.1"  # keep-alive targets
        s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        return s
    api_srv, web_srv = server("api"), server("web")
    elb = boto3.client("elbv2", **kw)
    lb = elb.create_load_balancer(Name=f"rules{run}")["LoadBalancers"][0]["LoadBalancerArn"]
    tg = {}
    for name, srv in (("api", api_srv), ("web", web_srv)):
        tg[name] = elb.create_target_group(Name=f"{name}{run}", Protocol="HTTP", Port=srv.server_port, VpcId="vpc-local", TargetType="ip")["TargetGroups"][0]["TargetGroupArn"]
        elb.register_targets(TargetGroupArn=tg[name], Targets=[{"Id": "127.0.0.1", "Port": srv.server_port}])
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]
    ln = elb.create_listener(LoadBalancerArn=lb, Protocol="HTTP", Port=port, DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["web"]}])["Listeners"][0]["ListenerArn"]
    elb.create_rule(ListenerArn=ln, Priority=10, Conditions=[{"Field": "path-pattern", "Values": ["/api/*"]}], Actions=[{"Type": "forward", "TargetGroupArn": tg["api"]}])
    elb.create_rule(ListenerArn=ln, Priority=20, Conditions=[{"Field": "host-header", "HostHeaderConfig": {"Values": ["admin.*"]}}],
                    Actions=[{"Type": "fixed-response", "FixedResponseConfig": {"StatusCode": "403", "MessageBody": "no admin"}}])
    assert code(elb.create_rule, ListenerArn=ln, Priority=10, Conditions=[{"Field": "path-pattern", "Values": ["/x"]}],
                Actions=[{"Type": "forward", "TargetGroupArn": tg["api"]}]) == "PriorityInUse"
    rules = elb.describe_rules(ListenerArn=ln)["Rules"]
    assert [r["Priority"] for r in rules] == ["10", "20", "default"] and rules[-1]["IsDefault"], rules
    get = lambda path, host=None: urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"Host": host} if host else {}), timeout=5).read()
    assert get("/api/orders?x=1") == b"api" and get("/") == b"web" and get("/apix") == b"web"
    import http.client  # one client connection, several requests: each is routed by its own path
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    for path, want in (("/api/a", b"api"), ("/b", b"web"), ("/api/c", b"api")):
        c.request("GET", path); r = c.getresponse()
        assert r.read() == want and r.getheader("connection") == "close", (path, r.getheaders())
    c.close()
    try:
        get("/", host="admin.local"); raise AssertionError("fixed 403 expected")
    except urllib.error.HTTPError as e:
        assert e.code == 403 and e.read() == b"no admin"
    assert code(elb.delete_target_group, TargetGroupArn=tg["api"]) == "ResourceInUse"  # used by a rule
    for r in rules[:-1]:
        elb.delete_rule(RuleArn=r["RuleArn"])
    assert get("/api/orders") == b"web"
    elb.delete_listener(ListenerArn=ln); elb.delete_load_balancer(LoadBalancerArn=lb)
    for a in tg.values():
        elb.delete_target_group(TargetGroupArn=a)
    api_srv.shutdown(); web_srv.shutdown()


def test_route53():
    import dns.resolver, dns.rcode
    r53 = boto3.client("route53", **kw)
    zone = f"shop{run}.test"
    z = r53.create_hosted_zone(Name=zone, CallerReference=run)["HostedZone"]["Id"]
    assert code(r53.create_hosted_zone, Name=zone, CallerReference=run) == "HostedZoneAlreadyExists"
    rr = lambda name, ty, vals: {"Name": name, "Type": ty, "TTL": 60, "ResourceRecords": [{"Value": v} for v in vals]}
    r53.change_resource_record_sets(HostedZoneId=z, ChangeBatch={"Changes": [
        {"Action": "CREATE", "ResourceRecordSet": rr(f"api.{zone}", "A", ["10.0.0.1", "10.0.0.2"])},
        {"Action": "CREATE", "ResourceRecordSet": rr(f"www.{zone}", "CNAME", [f"api.{zone}"])},
        {"Action": "CREATE", "ResourceRecordSet": rr(zone, "TXT", ['"v=spf1 -all"'])},
        {"Action": "CREATE", "ResourceRecordSet": rr(f"*.dev.{zone}", "A", ["10.9.9.9"])},
        {"Action": "CREATE", "ResourceRecordSet": {"Name": f"lb.{zone}", "Type": "A",
            "AliasTarget": {"HostedZoneId": "Z1", "DNSName": "my-alb.local", "EvaluateTargetHealth": False}}}]})
    assert code(r53.change_resource_record_sets, HostedZoneId=z, ChangeBatch={"Changes": [
        {"Action": "CREATE", "ResourceRecordSet": rr(f"api.{zone}", "A", ["1.1.1.1"])}]}) == "InvalidChangeBatch"
    sets = r53.list_resource_record_sets(HostedZoneId=z)["ResourceRecordSets"]
    assert {(s["Name"], s["Type"]) for s in sets} >= {(f"api.{zone}.", "A"), (f"{zone}.", "SOA"), (f"{zone}.", "NS")}, sets

    res = dns.resolver.Resolver(configure=False)
    res.nameservers, res.port = ["127.0.0.1"], int(os.environ.get("RC_DNS_PORT", "10053"))
    q = lambda name, t="A": sorted(x.to_text() for x in res.resolve(name, t))
    assert q(f"api.{zone}") == ["10.0.0.1", "10.0.0.2"]
    assert q(f"www.{zone}") == ["10.0.0.1", "10.0.0.2"]  # CNAME chased
    assert q(zone, "TXT") == ['"v=spf1 -all"']
    assert q(f"feature-x.dev.{zone}") == ["10.9.9.9"]  # wildcard
    assert q(f"lb.{zone}") == ["127.0.0.1"]  # alias to a local resource
    try:
        res.resolve(f"nope.{zone}"); raise AssertionError
    except dns.resolver.NXDOMAIN:
        pass

    r53.change_resource_record_sets(HostedZoneId=z, ChangeBatch={"Changes": [
        {"Action": "UPSERT", "ResourceRecordSet": rr(f"api.{zone}", "A", ["10.0.0.3"])}]})
    assert q(f"api.{zone}") == ["10.0.0.3"]
    assert code(r53.delete_hosted_zone, Id=z) == "HostedZoneNotEmpty"
    for s in r53.list_resource_record_sets(HostedZoneId=z)["ResourceRecordSets"]:
        if s["Type"] not in ("SOA", "NS"):
            r53.change_resource_record_sets(HostedZoneId=z, ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": s}]})
    r53.delete_hosted_zone(Id=z)
    assert code(r53.get_hosted_zone, Id=z) == "NoSuchHostedZone"


CFN_TEMPLATE = """
Parameters:
  Env: {Type: String, Default: dev, AllowedValues: [dev, prod]}
Conditions:
  IsProd: !Equals [!Ref Env, prod]
Mappings:
  Sizes: {dev: {Timeout: "5"}, prod: {Timeout: "30"}}
Resources:
  Table:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PAY_PER_REQUEST
      KeySchema: [{AttributeName: id, KeyType: HASH}]
      AttributeDefinitions: [{AttributeName: id, AttributeType: S}]
  Dlq:
    Type: AWS::SQS::Queue
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      VisibilityTimeout: !FindInMap [Sizes, !Ref Env, Timeout]
      RedrivePolicy: {deadLetterTargetArn: !GetAtt Dlq.Arn, maxReceiveCount: 3}
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription: [{Protocol: sqs, Endpoint: !GetAtt Queue.Arn}]
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement: [{Effect: Allow, Principal: {Service: lambda.amazonaws.com}, Action: sts:AssumeRole}]
      Policies:
        - PolicyName: ddb
          PolicyDocument:
            Statement: [{Effect: Allow, Action: dynamodb:PutItem, Resource: !GetAtt Table.Arn}]
  Fn:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt Role.Arn
      Environment: {Variables: {TABLE: !Ref Table, ENV: !Ref Env}}
      Code:
        ZipFile: |
          import os
          def handler(event, ctx):
              return {"table": os.environ["TABLE"], "env": os.environ["ENV"]}
  Param:
    Type: AWS::SSM::Parameter
    Properties:
      Name: !Sub "/${AWS::StackName}/queue"
      Type: String
      Value: !Ref Queue
  Secret:
    Type: AWS::SecretsManager::Secret
    Properties:
      GenerateSecretString: {SecretStringTemplate: '{"user": "app"}', GenerateStringKey: password, PasswordLength: 20}
  ProdOnly:
    Type: AWS::S3::Bucket
    Condition: IsProd
Outputs:
  QueueUrl: {Value: !Ref Queue}
  FnArn: {Value: !GetAtt Fn.Arn}
  TableName: {Value: !Ref Table}
  Label: {Value: !Join ["-", [!Ref "AWS::StackName", !Ref Env]]}
"""


def test_cloudformation():
    cf, lam, sns, ssm, sm = (boto3.client(n, **kw) for n in ("cloudformation", "lambda", "sns", "ssm", "secretsmanager"))
    name = f"app{run}"

    def wait(target, stack=name):
        for _ in range(200):
            st = cf.describe_stacks(StackName=stack)["Stacks"][0]
            if not st["StackStatus"].endswith("_IN_PROGRESS"):
                assert st["StackStatus"] == target, (st["StackStatus"], st.get("StackStatusReason"))
                return st
            time.sleep(0.1)
        raise AssertionError("stack never settled")

    cf.create_stack(StackName=name, TemplateBody=CFN_TEMPLATE)
    st = wait("CREATE_COMPLETE")
    out = {o["OutputKey"]: o["OutputValue"] for o in st["Outputs"]}
    assert out["Label"] == f"{name}-dev"
    res = {r["LogicalResourceId"]: r for r in cf.describe_stack_resources(StackName=name)["StackResources"]}
    assert set(res) == {"Table", "Dlq", "Queue", "Topic", "Role", "Fn", "Param", "Secret"}, set(res)  # ProdOnly skipped by condition
    assert sqs.get_queue_attributes(QueueUrl=out["QueueUrl"], AttributeNames=["VisibilityTimeout"])["Attributes"]["VisibilityTimeout"] == "5"
    sns.publish(TopicArn=res["Topic"]["PhysicalResourceId"], Message="via-stack")
    assert "via-stack" in sqs.receive_message(QueueUrl=out["QueueUrl"])["Messages"][0]["Body"]
    assert json.loads(lam.invoke(FunctionName=out["FnArn"])["Payload"].read()) == {"table": out["TableName"], "env": "dev"}
    assert ssm.get_parameter(Name=f"/{name}/queue")["Parameter"]["Value"] == out["QueueUrl"]
    secret = json.loads(sm.get_secret_value(SecretId=res["Secret"]["PhysicalResourceId"])["SecretString"])
    assert secret["user"] == "app" and len(secret["password"]) == 20

    cf.update_stack(StackName=name, UsePreviousTemplate=True, Parameters=[{"ParameterKey": "Env", "ParameterValue": "prod"}])
    st = wait("UPDATE_COMPLETE")
    res2 = {r["LogicalResourceId"]: r for r in cf.describe_stack_resources(StackName=name)["StackResources"]}
    assert "ProdOnly" in res2 and res2["Table"]["PhysicalResourceId"] == res["Table"]["PhysicalResourceId"]  # unchanged → kept
    q2 = {o["OutputKey"]: o["OutputValue"] for o in st["Outputs"]}["QueueUrl"]
    assert sqs.get_queue_attributes(QueueUrl=q2, AttributeNames=["VisibilityTimeout"])["Attributes"]["VisibilityTimeout"] == "30"
    assert code(cf.update_stack, StackName=name, UsePreviousTemplate=True, Parameters=[{"ParameterKey": "Env", "ParameterValue": "prod"}]) == "ValidationError"

    bad = f"bad{run}"
    cf.create_stack(StackName=bad, TemplateBody="Resources:\n  Q: {Type: AWS::SQS::Queue}\n  X: {Type: AWS::Nope::Thing, DependsOn: Q}\n")
    st = wait("ROLLBACK_COMPLETE", bad)
    assert "not supported" in st["StackStatusReason"]
    assert not [u for u in sqs.list_queues().get("QueueUrls", []) if f"{bad}-Q-" in u], "rollback removes created resources"
    cf.delete_stack(StackName=bad)

    cf.delete_stack(StackName=name)
    cf.get_waiter("stack_delete_complete").wait(StackName=name, WaiterConfig={"Delay": 1})
    assert code(ddb.describe_table, TableName=out["TableName"]) == "ResourceNotFoundException"
    assert code(cf.describe_stacks, StackName=name) == "ValidationError"


def test_agent():
    import urllib.request
    H = {"x-rocalcloud": "1", "content-type": "application/json"}
    post = lambda u, b: json.load(urllib.request.urlopen(urllib.request.Request(EP + u, data=json.dumps(b).encode(), headers=H, method="POST"), timeout=300))
    t = f"agent{run}"
    ddb.create_table(TableName=t, BillingMode="PAY_PER_REQUEST", KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                     AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}])
    ddb.put_item(TableName=t, Item={"id": {"S": "a"}})
    rid = None
    try:
        ddb.put_item(TableName=t, Item={"id": {"S": "a"}}, ConditionExpression="attribute_not_exists(id)")
    except ClientError as e:
        rid = e.response["ResponseMetadata"]["RequestId"]
    quick = post("/_agent/explain", {"request_id": rid, "llm": False})
    assert quick["rule"].startswith("ConditionalCheckFailedException"), quick
    st = json.load(urllib.request.urlopen(EP + "/_agent/status"))
    if st["available"]:
        full = post("/_agent/explain", {"request_id": rid})
        assert full["llm"] and len(full["llm"]) > 10, full
        r = post("/_agent/ask", {"question": f"{t} 테이블을 지워줘"})
        assert r.get("confirm", {}).get("operation") == "DeleteTable", r  # destructive → needs confirmation
        assert t in ddb.list_tables()["TableNames"], "nothing deleted before confirmation"
        done = post("/_agent/ask", {"confirm": r["confirm"]["needs_confirmation"]})
        assert t not in ddb.list_tables()["TableNames"], done
        print("   explain:", full["llm"][:160].replace("\n", " "))
        print("   ask steps:", [(x["action"], x["args"].get("service"), x["args"].get("operation")) for x in r["steps"]])
    else:
        ddb.delete_table(TableName=t)
        assert "규칙 기반" in post("/_agent/ask", {"question": "최근 오류?"})["answer"]


def test_template_roundtrip():
    import urllib.request
    sns, ssm, cf = boto3.client("sns", **kw), boto3.client("ssm", **kw), boto3.client("cloudformation", **kw)
    urllib.request.urlopen(urllib.request.Request(f"{EP}/_admin/reset", headers={"x-rocalcloud": "1"}, method="POST"))
    p = f"rt{run}"
    ddb.create_table(TableName=f"{p}-orders", BillingMode="PAY_PER_REQUEST", KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                     AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}])
    dlq = sqs.create_queue(QueueName=f"{p}-dlq")["QueueUrl"]
    q = sqs.create_queue(QueueName=f"{p}-jobs", Attributes={"VisibilityTimeout": "45", "RedrivePolicy": json.dumps(
        {"deadLetterTargetArn": f"arn:aws:sqs:us-east-1:000000000000:{p}-dlq", "maxReceiveCount": "4"})})["QueueUrl"]
    t = sns.create_topic(Name=f"{p}-events")["TopicArn"]
    sns.subscribe(TopicArn=t, Protocol="sqs", Endpoint=f"arn:aws:sqs:us-east-1:000000000000:{p}-jobs", Attributes={"RawMessageDelivery": "true"})
    s3.create_bucket(Bucket=f"{p}-files")
    ssm.put_parameter(Name=f"/{p}/mode", Value="fast", Type="String")
    yaml = urllib.request.urlopen(f"{EP}/_agent/template").read().decode()
    assert "AWS::SNS::Subscription" in yaml and "Fn::GetAtt" in yaml, yaml
    urllib.request.urlopen(urllib.request.Request(f"{EP}/_admin/reset", headers={"x-rocalcloud": "1"}, method="POST"))
    assert not sqs.list_queues().get("QueueUrls")
    cf.create_stack(StackName=p, TemplateBody=yaml)
    for _ in range(100):
        st = cf.describe_stacks(StackName=p)["Stacks"][0]["StackStatus"]
        if not st.endswith("IN_PROGRESS"):
            break
        time.sleep(0.1)
    assert st == "CREATE_COMPLETE", cf.describe_stacks(StackName=p)["Stacks"][0]
    a = sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["All"])["Attributes"]
    assert a["VisibilityTimeout"] == "45" and json.loads(a["RedrivePolicy"])["maxReceiveCount"] in (4, "4"), a
    sns.publish(TopicArn=t, Message="again")
    assert sqs.receive_message(QueueUrl=q)["Messages"][0]["Body"] == "again"
    assert ddb.describe_table(TableName=f"{p}-orders")["Table"]["KeySchema"][0]["AttributeName"] == "id"
    assert ssm.get_parameter(Name=f"/{p}/mode")["Parameter"]["Value"] == "fast"
    cf.delete_stack(StackName=p)


def test_inspector():
    import urllib.request, urllib.error
    H = {"x-rocalcloud": "1", "content-type": "application/json"}
    post = lambda u, b: json.load(urllib.request.urlopen(urllib.request.Request(EP + u, data=json.dumps(b).encode(), headers=H, method="POST"), timeout=120))
    # CSRF header required on POST /_inspect/run
    try:
        urllib.request.urlopen(urllib.request.Request(EP + "/_inspect/run", data=b"{}", headers={"content-type": "application/json"}, method="POST"))
        raise AssertionError("expected 403 without x-rocalcloud header")
    except urllib.error.HTTPError as e:
        assert e.code == 403, e.code
    # Full deterministic run (all built-in kinds)
    rep = post("/_inspect/run", {"use_llm": False})
    failed = [r for r in rep["results"] if not r["passed"]]
    assert rep["summary"]["total"] >= 13 and rep["summary"]["failed"] == 0, failed
    assert rep["enforce_iam"] is True, "sdk_test must run with ENFORCE_IAM=1"
    rid = rep["id"]
    # Reports list + Markdown / HTML exports
    lst = json.load(urllib.request.urlopen(EP + "/_inspect/reports"))
    assert lst["latest"]["id"] == rid and len(lst["runs"]) >= 1
    md = urllib.request.urlopen(f"{EP}/_inspect/report/{rid}?format=md").read().decode()
    html = urllib.request.urlopen(f"{EP}/_inspect/report/{rid}?format=html").read().decode()
    assert f"({rid})" in md and "| PASS |" in md, md[:200]
    assert f"({rid})" in html and "PASS" in html, html[:200]
    # Replay a single custom scenario
    replayed = post("/_inspect/replay", {
        "id": "custom-replay", "name": "단일 재현", "service": "dynamodb",
        "steps": [{"service": "dynamodb", "op": "DescribeTable", "params": {"TableName": "rc-insp-does-not-exist"}}],
        "expect": {"status": 400, "error_code": "ResourceNotFoundException"},
    })
    assert replayed["passed"], replayed
    # Verify cleanup: no leftover rc-insp- resources or chaos rules
    assert not [b["Name"] for b in s3.list_buckets()["Buckets"] if b["Name"].startswith("rc-insp-")]
    assert not [t for t in ddb.list_tables()["TableNames"] if t.startswith("rc-insp-")]
    assert not [u for u in sqs.list_queues().get("QueueUrls", []) if "rc-insp-" in u]
    assert json.load(urllib.request.urlopen(EP + "/_admin/chaos"))["rules"] == []


def test_snapshot():
    import urllib.request
    H = {"x-rocalcloud": "1", "content-type": "application/json"}
    sns, ssm, sm, kms, iam = (boto3.client(n, **kw) for n in ("sns", "ssm", "secretsmanager", "kms", "iam"))
    p = f"snap{run}"
    ddb.create_table(TableName=p, BillingMode="PAY_PER_REQUEST", KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                     AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}])
    ddb.put_item(TableName=p, Item={"id": {"S": "k1"}, "v": {"S": "saved"}})
    s3.create_bucket(Bucket=p)
    s3.put_object(Bucket=p, Key="a.txt", Body=b"hello-snap", ContentType="text/plain")
    q = sqs.create_queue(QueueName=p)["QueueUrl"]
    sqs.send_message(QueueUrl=q, MessageBody="queued-msg")
    t = sns.create_topic(Name=p)["TopicArn"]
    sns.subscribe(TopicArn=t, Protocol="sqs", Endpoint=f"arn:aws:sqs:us-east-1:000000000000:{p}", Attributes={"RawMessageDelivery": "true"})
    ssm.put_parameter(Name=f"/{p}/k", Value="v1", Type="String")
    sm.create_secret(Name=p, SecretString="s-val")
    kid = kms.create_key(Description=p)["KeyMetadata"]["KeyId"]
    ct = kms.encrypt(KeyId=kid, Plaintext=b"kms-secret")["CiphertextBlob"]
    iam.create_user(UserName=p)
    ak = iam.create_access_key(UserName=p)["AccessKey"]
    iam.put_user_policy(UserName=p, PolicyName="allow", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{p}/*"}]}))

    snap = urllib.request.urlopen(f"{EP}/_admin/snapshot").read()
    urllib.request.urlopen(urllib.request.Request(f"{EP}/_admin/reset", headers={"x-rocalcloud": "1"}, method="POST"))
    assert p not in ddb.list_tables()["TableNames"]
    assert not [b for b in s3.list_buckets()["Buckets"] if b["Name"] == p]

    res = json.load(urllib.request.urlopen(urllib.request.Request(f"{EP}/_admin/snapshot", data=snap, headers=H, method="POST")))
    assert res["restored"] is True, res
    assert ddb.get_item(TableName=p, Key={"id": {"S": "k1"}})["Item"]["v"]["S"] == "saved"
    assert s3.get_object(Bucket=p, Key="a.txt")["Body"].read() == b"hello-snap"
    assert sqs.receive_message(QueueUrl=q)["Messages"][0]["Body"] == "queued-msg"
    assert ssm.get_parameter(Name=f"/{p}/k")["Parameter"]["Value"] == "v1"
    assert sm.get_secret_value(SecretId=p)["SecretString"] == "s-val"
    assert kms.decrypt(CiphertextBlob=ct)["Plaintext"] == b"kms-secret"
    # Restored IAM user & policy still enforced
    u_s3 = boto3.client("s3", endpoint_url=EP, region_name="us-east-1",
                        aws_access_key_id=ak["AccessKeyId"], aws_secret_access_key=ak["SecretAccessKey"])
    assert u_s3.get_object(Bucket=p, Key="a.txt")["Body"].read() == b"hello-snap"
    assert code(u_s3.list_buckets) == "AccessDenied"
    urllib.request.urlopen(urllib.request.Request(f"{EP}/_admin/reset", headers={"x-rocalcloud": "1"}, method="POST"))


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            try:
                fn()
                print("ok", name)
            except Skip as e:
                print("skip", name, f"({e})")
