// Official AWS SDK for JavaScript v3 compatibility suite for rocalcloud.
// Run against a server started with ENFORCE_IAM=1:
//   cd tests/js && npm install && npm test
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { DynamoDBClient, CreateTableCommand, PutItemCommand, GetItemCommand, QueryCommand, DeleteTableCommand } from "@aws-sdk/client-dynamodb";
import { S3Client, CreateBucketCommand, PutObjectCommand, GetObjectCommand, ListObjectsV2Command, DeleteObjectCommand, DeleteBucketCommand } from "@aws-sdk/client-s3";
import { SQSClient, CreateQueueCommand, SendMessageCommand, ReceiveMessageCommand, DeleteMessageCommand, DeleteQueueCommand, GetQueueUrlCommand } from "@aws-sdk/client-sqs";
import { IAMClient, CreateUserCommand, CreateAccessKeyCommand, PutUserPolicyCommand, DeleteUserPolicyCommand, DeleteAccessKeyCommand, DeleteUserCommand } from "@aws-sdk/client-iam";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { SSMClient, PutParameterCommand, GetParameterCommand, DeleteParameterCommand } from "@aws-sdk/client-ssm";
import { SecretsManagerClient, CreateSecretCommand, GetSecretValueCommand, DeleteSecretCommand } from "@aws-sdk/client-secrets-manager";
import { KMSClient, CreateKeyCommand, EncryptCommand, DecryptCommand } from "@aws-sdk/client-kms";
import { SNSClient, CreateTopicCommand, SubscribeCommand, PublishCommand, DeleteTopicCommand } from "@aws-sdk/client-sns";

const endpoint = process.env.ROCALCLOUD_URL || "http://127.0.0.1:4566";
const region = process.env.REGION || "us-east-1";
const run = crypto.randomBytes(4).toString("hex");
const cfg = (akid = "test", secret = "test") => ({ endpoint, region, credentials: { accessKeyId: akid, secretAccessKey: secret } });

async function expectError(fn, expected) {
  try {
    await fn();
  } catch (e) {
    const code = e.name || e.Code || "";
    assert.ok(expected.includes(code), `expected error in ${JSON.stringify(expected)}, got ${code}: ${e.message}`);
    return;
  }
  assert.fail(`expected error ${JSON.stringify(expected)}, but call succeeded`);
}

async function testDynamoDB() {
  const ddb = new DynamoDBClient(cfg());
  const TableName = `js-orders-${run}`;
  await ddb.send(new CreateTableCommand({
    TableName, BillingMode: "PAY_PER_REQUEST",
    KeySchema: [{ AttributeName: "pk", KeyType: "HASH" }, { AttributeName: "sk", KeyType: "RANGE" }],
    AttributeDefinitions: [{ AttributeName: "pk", AttributeType: "S" }, { AttributeName: "sk", AttributeType: "S" }],
  }));
  await ddb.send(new PutItemCommand({ TableName, Item: { pk: { S: "u1" }, sk: { S: "o1" }, total: { N: "42" } } }));
  const got = await ddb.send(new GetItemCommand({ TableName, Key: { pk: { S: "u1" }, sk: { S: "o1" } } }));
  assert.equal(got.Item.total.N, "42");
  const q = await ddb.send(new QueryCommand({
    TableName, KeyConditionExpression: "pk = :p AND begins_with(sk, :s)",
    ExpressionAttributeValues: { ":p": { S: "u1" }, ":s": { S: "o" } },
  }));
  assert.equal(q.Count, 1);
  await expectError(
    () => ddb.send(new PutItemCommand({ TableName, Item: { pk: { S: "u1" }, sk: { S: "o1" } }, ConditionExpression: "attribute_not_exists(pk)" })),
    ["ConditionalCheckFailedException"],
  );
  await ddb.send(new DeleteTableCommand({ TableName }));
}

async function testS3() {
  const s3 = new S3Client({ ...cfg(), forcePathStyle: true });
  const Bucket = `js-bkt-${run}`;
  await s3.send(new CreateBucketCommand({ Bucket }));
  await s3.send(new PutObjectCommand({ Bucket, Key: "dir/hello.txt", Body: "hello-js-sdk", ContentType: "text/plain" }));
  const obj = await s3.send(new GetObjectCommand({ Bucket, Key: "dir/hello.txt" }));
  assert.equal(await obj.Body.transformToString(), "hello-js-sdk");
  const list = await s3.send(new ListObjectsV2Command({ Bucket, Prefix: "dir/" }));
  assert.equal(list.Contents.length, 1);
  assert.equal(list.Contents[0].Key, "dir/hello.txt");
  await expectError(() => s3.send(new GetObjectCommand({ Bucket, Key: "missing.txt" })), ["NoSuchKey"]);
  await s3.send(new DeleteObjectCommand({ Bucket, Key: "dir/hello.txt" }));
  await s3.send(new DeleteBucketCommand({ Bucket }));
}

async function testSQSAndSNS() {
  const sqs = new SQSClient(cfg());
  const sns = new SNSClient(cfg());
  const qName = `js-q-${run}`;
  const { QueueUrl } = await sqs.send(new CreateQueueCommand({ QueueName: qName }));
  await sqs.send(new SendMessageCommand({ QueueUrl, MessageBody: "direct-msg" }));
  const r1 = await sqs.send(new ReceiveMessageCommand({ QueueUrl, MaxNumberOfMessages: 1 }));
  assert.equal(r1.Messages[0].Body, "direct-msg");
  await sqs.send(new DeleteMessageCommand({ QueueUrl, ReceiptHandle: r1.Messages[0].ReceiptHandle }));

  const { TopicArn } = await sns.send(new CreateTopicCommand({ Name: `js-topic-${run}` }));
  await sns.send(new SubscribeCommand({
    TopicArn, Protocol: "sqs", Endpoint: `arn:aws:sqs:${region}:000000000000:${qName}`,
    Attributes: { RawMessageDelivery: "true" },
  }));
  await sns.send(new PublishCommand({ TopicArn, Message: "via-sns-js" }));
  const r2 = await sqs.send(new ReceiveMessageCommand({ QueueUrl, MaxNumberOfMessages: 1 }));
  assert.equal(r2.Messages[0].Body, "via-sns-js");

  await expectError(() => sqs.send(new GetQueueUrlCommand({ QueueName: `nope-${run}` })), ["QueueDoesNotExist"]);
  await sns.send(new DeleteTopicCommand({ TopicArn }));
  await sqs.send(new DeleteQueueCommand({ QueueUrl }));
}

async function testIAMAndSTS() {
  const iam = new IAMClient(cfg());
  const sts = new STSClient(cfg());
  const s3Root = new S3Client({ ...cfg(), forcePathStyle: true });
  const who = await sts.send(new GetCallerIdentityCommand({}));
  assert.equal(who.Account, "000000000000");

  const UserName = `js-user-${run}`;
  const Bucket = `js-iam-${run}`;
  await s3Root.send(new CreateBucketCommand({ Bucket }));
  await s3Root.send(new PutObjectCommand({ Bucket, Key: "k.txt", Body: "secret" }));
  await iam.send(new CreateUserCommand({ UserName }));
  const { AccessKey } = await iam.send(new CreateAccessKeyCommand({ UserName }));
  const s3User = new S3Client({ ...cfg(AccessKey.AccessKeyId, AccessKey.SecretAccessKey), forcePathStyle: true });

  // Implicit deny
  await expectError(() => s3User.send(new GetObjectCommand({ Bucket, Key: "k.txt" })), ["AccessDenied"]);
  // Allow
  await iam.send(new PutUserPolicyCommand({
    UserName, PolicyName: "allow",
    PolicyDocument: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "s3:GetObject", Resource: `arn:aws:s3:::${Bucket}/*` }] }),
  }));
  const got = await s3User.send(new GetObjectCommand({ Bucket, Key: "k.txt" }));
  assert.equal(await got.Body.transformToString(), "secret");
  // Explicit deny overrides allow
  await iam.send(new PutUserPolicyCommand({
    UserName, PolicyName: "deny",
    PolicyDocument: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Deny", Action: "s3:GetObject", Resource: `arn:aws:s3:::${Bucket}/*` }] }),
  }));
  await expectError(() => s3User.send(new GetObjectCommand({ Bucket, Key: "k.txt" })), ["AccessDenied"]);

  // Cleanup
  await iam.send(new DeleteUserPolicyCommand({ UserName, PolicyName: "allow" }));
  await iam.send(new DeleteUserPolicyCommand({ UserName, PolicyName: "deny" }));
  await iam.send(new DeleteAccessKeyCommand({ UserName, AccessKeyId: AccessKey.AccessKeyId }));
  await iam.send(new DeleteUserCommand({ UserName }));
  await s3Root.send(new DeleteObjectCommand({ Bucket, Key: "k.txt" }));
  await s3Root.send(new DeleteBucketCommand({ Bucket }));
}

async function testSSMSecretsKMS() {
  const ssm = new SSMClient(cfg());
  const sm = new SecretsManagerClient(cfg());
  const kms = new KMSClient(cfg());
  const pname = `/js/${run}/cfg`;
  await ssm.send(new PutParameterCommand({ Name: pname, Value: "v1", Type: "String" }));
  assert.equal((await ssm.send(new GetParameterCommand({ Name: pname }))).Parameter.Value, "v1");
  await ssm.send(new DeleteParameterCommand({ Name: pname }));

  const sname = `js-sec-${run}`;
  await sm.send(new CreateSecretCommand({ Name: sname, SecretString: "{\"k\":1}" }));
  assert.equal((await sm.send(new GetSecretValueCommand({ SecretId: sname }))).SecretString, "{\"k\":1}");
  await sm.send(new DeleteSecretCommand({ SecretId: sname, ForceDeleteWithoutRecovery: true }));

  const { KeyMetadata } = await kms.send(new CreateKeyCommand({ Description: "js-test" }));
  const enc = await kms.send(new EncryptCommand({ KeyId: KeyMetadata.KeyId, Plaintext: Buffer.from("hello-kms") }));
  const dec = await kms.send(new DecryptCommand({ CiphertextBlob: enc.CiphertextBlob }));
  assert.equal(Buffer.from(dec.Plaintext).toString("utf8"), "hello-kms");
}

for (const [name, fn] of [
  ["js_dynamodb", testDynamoDB],
  ["js_s3", testS3],
  ["js_sqs_sns", testSQSAndSNS],
  ["js_iam_sts", testIAMAndSTS],
  ["js_ssm_secrets_kms", testSSMSecretsKMS],
]) {
  await fn();
  console.log("ok", name);
}
