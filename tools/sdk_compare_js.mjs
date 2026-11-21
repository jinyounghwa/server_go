#!/usr/bin/env node
// JS (@aws-sdk v3) scenario runner for tools/sdk_compare.py.
// Prints normalized JSON results for identical operations so Python/JS/Rust responses can be diffed automatically.

import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const req = createRequire(path.join(here, "..", "tests", "js", "package.json"));

const { DynamoDBClient, CreateTableCommand, PutItemCommand, GetItemCommand, QueryCommand, DeleteTableCommand } = req("@aws-sdk/client-dynamodb");
const { S3Client, CreateBucketCommand, PutObjectCommand, GetObjectCommand, ListObjectsV2Command, DeleteObjectCommand, DeleteBucketCommand } = req("@aws-sdk/client-s3");
const { SQSClient, CreateQueueCommand, SendMessageCommand, ReceiveMessageCommand, DeleteMessageCommand, DeleteQueueCommand, GetQueueUrlCommand } = req("@aws-sdk/client-sqs");
const { SNSClient, CreateTopicCommand, PublishCommand, DeleteTopicCommand } = req("@aws-sdk/client-sns");
const { SSMClient, PutParameterCommand, GetParameterCommand, DeleteParameterCommand } = req("@aws-sdk/client-ssm");
const { SecretsManagerClient, CreateSecretCommand, GetSecretValueCommand, DeleteSecretCommand } = req("@aws-sdk/client-secrets-manager");
const { STSClient, GetCallerIdentityCommand } = req("@aws-sdk/client-sts");

const endpoint = process.env.ROCALCLOUD_URL || "http://127.0.0.1:4566";
const region = process.env.REGION || "us-east-1";
const tag = process.argv[2] || "cmp";
const cfg = { endpoint, region, credentials: { accessKeyId: "test", secretAccessKey: "test" } };

async function captureErr(fn) {
  try {
    await fn();
    return { ok: true, error: null };
  } catch (e) {
    return { ok: false, error: e.name || e.Code || "UnknownError" };
  }
}

async function run() {
  const out = {};

  // 1. STS
  const sts = new STSClient(cfg);
  const who = await sts.send(new GetCallerIdentityCommand({}));
  out.sts = { account: who.Account, arn: who.Arn };

  // 2. DynamoDB
  const ddb = new DynamoDBClient(cfg);
  const t = `cmp-ddb-${tag}`;
  await ddb.send(new CreateTableCommand({
    TableName: t, BillingMode: "PAY_PER_REQUEST",
    KeySchema: [{ AttributeName: "pk", KeyType: "HASH" }, { AttributeName: "sk", KeyType: "RANGE" }],
    AttributeDefinitions: [{ AttributeName: "pk", AttributeType: "S" }, { AttributeName: "sk", AttributeType: "S" }],
  }));
  await ddb.send(new PutItemCommand({ TableName: t, Item: { pk: { S: "u1" }, sk: { S: "o1" }, total: { N: "42" } } }));
  const got = await ddb.send(new GetItemCommand({ TableName: t, Key: { pk: { S: "u1" }, sk: { S: "o1" } } }));
  const q = await ddb.send(new QueryCommand({
    TableName: t, KeyConditionExpression: "pk = :p AND begins_with(sk, :s)",
    ExpressionAttributeValues: { ":p": { S: "u1" }, ":s": { S: "o" } },
  }));
  const condErr = await captureErr(() => ddb.send(new PutItemCommand({
    TableName: t, Item: { pk: { S: "u1" }, sk: { S: "o1" } }, ConditionExpression: "attribute_not_exists(pk)",
  })));
  await ddb.send(new DeleteTableCommand({ TableName: t }));
  out.dynamodb = {
    get_total: got.Item?.total?.N ?? null,
    query_count: q.Count,
    cond_err: condErr.error,
  };

  // 3. S3
  const s3 = new S3Client({ ...cfg, forcePathStyle: true });
  const b = `cmp-s3-${tag}`;
  await s3.send(new CreateBucketCommand({ Bucket: b }));
  await s3.send(new PutObjectCommand({ Bucket: b, Key: "a/hello.txt", Body: "hello-compare", ContentType: "text/plain" }));
  const obj = await s3.send(new GetObjectCommand({ Bucket: b, Key: "a/hello.txt" }));
  const body = await obj.Body.transformToString();
  const lst = await s3.send(new ListObjectsV2Command({ Bucket: b, Prefix: "a/" }));
  const missErr = await captureErr(() => s3.send(new GetObjectCommand({ Bucket: b, Key: "missing.txt" })));
  await s3.send(new DeleteObjectCommand({ Bucket: b, Key: "a/hello.txt" }));
  await s3.send(new DeleteBucketCommand({ Bucket: b }));
  out.s3 = {
    body,
    keys: (lst.Contents || []).map(x => x.Key),
    missing_err: missErr.error,
  };

  // 4. SQS
  const sqs = new SQSClient(cfg);
  const qn = `cmp-sqs-${tag}`;
  const { QueueUrl } = await sqs.send(new CreateQueueCommand({ QueueName: qn }));
  await sqs.send(new SendMessageCommand({ QueueUrl, MessageBody: "msg-compare" }));
  const rcv = await sqs.send(new ReceiveMessageCommand({ QueueUrl, MaxNumberOfMessages: 1 }));
  const msgBody = rcv.Messages?.[0]?.Body ?? null;
  if (rcv.Messages?.[0]?.ReceiptHandle) {
    await sqs.send(new DeleteMessageCommand({ QueueUrl, ReceiptHandle: rcv.Messages[0].ReceiptHandle }));
  }
  const qErr = await captureErr(() => sqs.send(new GetQueueUrlCommand({ QueueName: `nope-${tag}` })));
  await sqs.send(new DeleteQueueCommand({ QueueUrl }));
  out.sqs = { body: msgBody, missing_err: qErr.error };

  // 5. SNS
  const sns = new SNSClient(cfg);
  const { TopicArn } = await sns.send(new CreateTopicCommand({ Name: `cmp-sns-${tag}` }));
  const pub = await sns.send(new PublishCommand({ TopicArn, Message: "hi" }));
  await sns.send(new DeleteTopicCommand({ TopicArn }));
  out.sns = { has_message_id: Boolean(pub.MessageId), arn_suffix: TopicArn.endsWith(`:cmp-sns-${tag}`) };

  // 6. SSM
  const ssm = new SSMClient(cfg);
  const pn = `/cmp/${tag}/p`;
  await ssm.send(new PutParameterCommand({ Name: pn, Value: "v1", Type: "String" }));
  const pv = await ssm.send(new GetParameterCommand({ Name: pn }));
  await ssm.send(new DeleteParameterCommand({ Name: pn }));
  out.ssm = { value: pv.Parameter?.Value ?? null, type: pv.Parameter?.Type ?? null };

  // 7. Secrets Manager
  const sm = new SecretsManagerClient(cfg);
  const sn = `cmp-sec-${tag}`;
  await sm.send(new CreateSecretCommand({ Name: sn, SecretString: "{\"k\":1}" }));
  const sv = await sm.send(new GetSecretValueCommand({ SecretId: sn }));
  await sm.send(new DeleteSecretCommand({ SecretId: sn, ForceDeleteWithoutRecovery: true }));
  out.secretsmanager = { secret: sv.SecretString ?? null };

  console.log(JSON.stringify(out));
}

run().catch(e => {
  console.error(e);
  process.exit(1);
});
