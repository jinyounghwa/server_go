// Official AWS SDK for JavaScript v3 compatibility suite for rocalcloud.
// Run against a server started with ENFORCE_IAM=1:
//   cd tests/js && npm install && npm test
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { DynamoDBClient, CreateTableCommand, PutItemCommand, GetItemCommand, UpdateItemCommand, QueryCommand, DeleteTableCommand } from "@aws-sdk/client-dynamodb";
import { S3Client, CreateBucketCommand, PutObjectCommand, GetObjectCommand, ListObjectsV2Command, PutBucketPolicyCommand, DeleteBucketPolicyCommand, DeleteObjectCommand, DeleteBucketCommand } from "@aws-sdk/client-s3";
import { SQSClient, CreateQueueCommand, SendMessageCommand, ReceiveMessageCommand, DeleteMessageCommand, DeleteQueueCommand, GetQueueUrlCommand } from "@aws-sdk/client-sqs";
import { IAMClient, CreateUserCommand, CreateAccessKeyCommand, PutUserPolicyCommand, DeleteUserPolicyCommand, DeleteAccessKeyCommand, DeleteUserCommand } from "@aws-sdk/client-iam";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { SSMClient, PutParameterCommand, GetParameterCommand, DeleteParameterCommand } from "@aws-sdk/client-ssm";
import { SecretsManagerClient, CreateSecretCommand, GetSecretValueCommand, DeleteSecretCommand } from "@aws-sdk/client-secrets-manager";
import { KMSClient, CreateKeyCommand, EncryptCommand, DecryptCommand } from "@aws-sdk/client-kms";
import { CognitoIdentityProviderClient, CreateUserPoolCommand, CreateUserPoolClientCommand, AdminCreateUserCommand, AdminSetUserPasswordCommand, InitiateAuthCommand, RespondToAuthChallengeCommand, DeleteUserPoolCommand } from "@aws-sdk/client-cognito-identity-provider";
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

async function testSNSFifo() {
  const sns = new SNSClient(cfg());
  const sqs = new SQSClient(cfg());
  const qName = `js-fq-${run}.fifo`;
  const tName = `js-ft-${run}.fifo`;
  const { QueueUrl } = await sqs.send(new CreateQueueCommand({ QueueName: qName, Attributes: { FifoQueue: "true", ContentBasedDeduplication: "true" } }));
  const { TopicArn } = await sns.send(new CreateTopicCommand({ Name: tName, Attributes: { FifoTopic: "true", ContentBasedDeduplication: "true" } }));
  await sns.send(new SubscribeCommand({
    TopicArn, Protocol: "sqs", Endpoint: `arn:aws:sqs:${region}:000000000000:${qName}`,
    Attributes: { RawMessageDelivery: "true" },
  }));
  await sns.send(new PublishCommand({ TopicArn, Message: "same-payload", MessageGroupId: "g1" }));
  await sns.send(new PublishCommand({ TopicArn, Message: "same-payload", MessageGroupId: "g1" }));
  const got = await sqs.send(new ReceiveMessageCommand({ QueueUrl, MaxNumberOfMessages: 5 }));
  assert.equal(got.Messages.length, 1);
  assert.equal(got.Messages[0].Body, "same-payload");
  await sns.send(new DeleteTopicCommand({ TopicArn }));
  await sqs.send(new DeleteQueueCommand({ QueueUrl }));
}

async function testDynamoDBDecimalAndNested() {
  const ddb = new DynamoDBClient(cfg());
  const TableName = `js-num-${run}`;
  await ddb.send(new CreateTableCommand({
    TableName, BillingMode: "PAY_PER_REQUEST",
    KeySchema: [{ AttributeName: "pk", KeyType: "HASH" }, { AttributeName: "sk", KeyType: "RANGE" }],
    AttributeDefinitions: [{ AttributeName: "pk", AttributeType: "S" }, { AttributeName: "sk", AttributeType: "N" }],
  }));
  const k1 = "90071992547409920001";
  const k2 = "90071992547409920002";
  await ddb.send(new PutItemCommand({ TableName, Item: { pk: { S: "p" }, sk: { N: k1 }, doc: { M: { items: { L: [{ M: { x: { N: "1" }, y: { N: "2" } } }] } } } } }));
  await ddb.send(new PutItemCommand({ TableName, Item: { pk: { S: "p" }, sk: { N: k2 } } }));
  await ddb.send(new UpdateItemCommand({
    TableName, Key: { pk: { S: "p" }, sk: { N: k1 } },
    UpdateExpression: "SET doc.items[0].x = :v",
    ExpressionAttributeValues: { ":v": { N: "99" } },
  }));
  const q = await ddb.send(new QueryCommand({
    TableName, KeyConditionExpression: "pk = :p AND sk BETWEEN :a AND :b",
    ExpressionAttributeValues: { ":p": { S: "p" }, ":a": { N: k1 }, ":b": { N: k2 } },
  }));
  assert.deepEqual(q.Items.map((i) => i.sk.N), [k1, k2]);
  assert.equal(q.Items[0].doc.M.items.L[0].M.x.N, "99");
  await ddb.send(new DeleteTableCommand({ TableName }));
}

async function testIAMConditionsAndBucketPolicy() {
  const iam = new IAMClient(cfg());
  const s3Root = new S3Client({ ...cfg(), forcePathStyle: true });
  const Bucket = `js-pol-${run}`;
  const UserName = `js-cond-${run}`;
  await s3Root.send(new CreateBucketCommand({ Bucket }));
  await s3Root.send(new PutObjectCommand({ Bucket, Key: "a.txt", Body: "ok" }));
  await iam.send(new CreateUserCommand({ UserName }));
  const { AccessKey } = await iam.send(new CreateAccessKeyCommand({ UserName }));
  await iam.send(new PutUserPolicyCommand({
    UserName, PolicyName: "ip-allow",
    PolicyDocument: JSON.stringify({
      Version: "2012-10-17",
      Statement: [{ Effect: "Allow", Action: "s3:GetObject", Resource: `arn:aws:s3:::${Bucket}/*`, Condition: { IpAddress: { "aws:SourceIp": "127.0.0.0/8" } } }],
    }),
  }));
  const s3User = new S3Client({ ...cfg(AccessKey.AccessKeyId, AccessKey.SecretAccessKey), forcePathStyle: true });
  const got = await s3User.send(new GetObjectCommand({ Bucket, Key: "a.txt" }));
  assert.equal(await got.Body.transformToString(), "ok");
  await s3Root.send(new PutBucketPolicyCommand({
    Bucket,
    Policy: JSON.stringify({
      Version: "2012-10-17",
      Statement: [{ Effect: "Deny", Principal: { AWS: `arn:aws:iam::000000000000:user/${UserName}` }, Action: "s3:GetObject", Resource: `arn:aws:s3:::${Bucket}/*` }],
    }),
  }));
  await expectError(() => s3User.send(new GetObjectCommand({ Bucket, Key: "a.txt" })), ["AccessDenied"]);
  await s3Root.send(new DeleteBucketPolicyCommand({ Bucket }));
  await iam.send(new DeleteUserPolicyCommand({ UserName, PolicyName: "ip-allow" }));
  await iam.send(new DeleteAccessKeyCommand({ UserName, AccessKeyId: AccessKey.AccessKeyId }));
  await iam.send(new DeleteUserCommand({ UserName }));
  await s3Root.send(new DeleteObjectCommand({ Bucket, Key: "a.txt" }));
  await s3Root.send(new DeleteBucketCommand({ Bucket }));
}

// USER_SRP_AUTH the way Amplify / amazon-cognito-identity-js computes it, on native BigInt.
async function testCognitoSrp() {
  const idp = new CognitoIdentityProviderClient(cfg());
  const N = BigInt("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF");
  const g = 2n;
  const modPow = (b, e, m) => { let r = 1n; b %= m; for (; e > 0n; e >>= 1n, b = (b * b) % m) if (e & 1n) r = (r * b) % m; return r; };
  const padHex = (n) => { let h = n.toString(16); if (h.length % 2) h = "0" + h; return "89abcdef".includes(h[0]) ? "00" + h : h; };
  const hexHash = (h) => BigInt("0x" + crypto.createHash("sha256").update(Buffer.from(h, "hex")).digest("hex"));
  const hmac = (k, m) => crypto.createHmac("sha256", k).update(m).digest();
  const k = hexHash(padHex(N) + padHex(g));

  const pool = (await idp.send(new CreateUserPoolCommand({ PoolName: `js-srp-${run}` }))).UserPool.Id;
  const cid = (await idp.send(new CreateUserPoolClientCommand({ UserPoolId: pool, ClientName: "amplify" }))).UserPoolClient.ClientId;
  await idp.send(new AdminCreateUserCommand({ UserPoolId: pool, Username: "amy" }));
  await idp.send(new AdminSetUserPasswordCommand({ UserPoolId: pool, Username: "amy", Password: "Str0ng!pass", Permanent: true }));
  const poolName = pool.split("_")[1];

  const login = async (password) => {
    const a = BigInt("0x" + crypto.randomBytes(32).toString("hex"));
    const A = modPow(g, a, N);
    const ch = await idp.send(new InitiateAuthCommand({ ClientId: cid, AuthFlow: "USER_SRP_AUTH", AuthParameters: { USERNAME: "amy", SRP_A: A.toString(16) } }));
    assert.equal(ch.ChallengeName, "PASSWORD_VERIFIER");
    const p = ch.ChallengeParameters;
    const B = BigInt("0x" + p.SRP_B), salt = BigInt("0x" + p.SALT), uid = p.USER_ID_FOR_SRP;
    const u = hexHash(padHex(A) + padHex(B));
    const x = hexHash(padHex(salt) + crypto.createHash("sha256").update(`${poolName}${uid}:${password}`).digest("hex"));
    const S = modPow(((B - k * modPow(g, x, N)) % N + N) % N, a + u * x, N);
    const key = hmac(hmac(Buffer.from(padHex(u), "hex"), Buffer.from(padHex(S), "hex")), "Caldera Derived Key\u0001").subarray(0, 16);
    const d = new Date();
    const ts = `${d.toUTCString().slice(0, 3)} ${d.toUTCString().slice(8, 11)} ${d.getUTCDate()} ${d.toISOString().slice(11, 19)} UTC ${d.getUTCFullYear()}`;
    const sig = hmac(key, Buffer.concat([Buffer.from(poolName), Buffer.from(uid), Buffer.from(p.SECRET_BLOCK, "base64"), Buffer.from(ts)])).toString("base64");
    return idp.send(new RespondToAuthChallengeCommand({ ClientId: cid, ChallengeName: "PASSWORD_VERIFIER", ChallengeResponses: {
      USERNAME: uid, PASSWORD_CLAIM_SECRET_BLOCK: p.SECRET_BLOCK, PASSWORD_CLAIM_SIGNATURE: sig, TIMESTAMP: ts } }));
  };
  const ok = await login("Str0ng!pass");
  assert.ok(ok.AuthenticationResult.IdToken);
  await expectError(() => login("Wr0ng!pass"), ["NotAuthorizedException"]);
  await idp.send(new DeleteUserPoolCommand({ UserPoolId: pool }));
}

for (const [name, fn] of [
  ["js_dynamodb", testDynamoDB],
  ["js_s3", testS3],
  ["js_sqs_sns", testSQSAndSNS],
  ["js_iam_sts", testIAMAndSTS],
  ["js_ssm_secrets_kms", testSSMSecretsKMS],
  ["js_sns_fifo", testSNSFifo],
  ["js_ddb_decimal_and_nested", testDynamoDBDecimalAndNested],
  ["js_iam_conditions_and_policy", testIAMConditionsAndBucketPolicy],
  ["js_cognito_srp", testCognitoSrp],
]) {
  await fn();
  console.log("ok", name);
}
