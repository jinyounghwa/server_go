# rocalcloud

A local, in-memory emulator for the cloud APIs your app actually uses. Point an official SDK at
`http://127.0.0.1:4566` and it works offline. Plan and roadmap: [local-cloud-emulator-plan.md](local-cloud-emulator-plan.md).

## Run

```sh
cd core && cargo run --release        # emulator on 127.0.0.1:4566 (BIND, REGION env vars)
cd gui && cargo run                   # desktop window (Tauri), or open http://127.0.0.1:4566/_ui
ENFORCE_IAM=1 cargo run --release & uv run --with boto3 tests/sdk_test.py  # official-SDK check
```

## Supported

| Service | Operations |
|---|---|
| DynamoDB | Create/Describe/List/DeleteTable, Put/Get/Update/DeleteItem, Query, Scan, BatchWrite/GetItem, TransactWrite/GetItems, GSI/LSI, condition/filter/update/projection expressions |
| S3 | List/Create/Head/DeleteBucket, Put/Get/Head/Delete/CopyObject, Range, ListObjects(V2) with prefix/delimiter/paging, DeleteObjects, multipart upload, presigned URLs |
| SQS | Create/Delete/List/PurgeQueue, GetQueueUrl, Get/SetQueueAttributes, Send/Receive/DeleteMessage (+Batch), ChangeMessageVisibility, long polling, dead-letter queues |
| IAM / STS | Users, roles, managed + inline policies, access keys, SimulatePrincipalPolicy, AssumeRole (trust policy checked), GetCallerIdentity |
| SNS | Topics, subscriptions (SQS, Lambda), filter policies, raw delivery, topic/subscription attributes |
| Secrets Manager | Create/Get/Put/Update/Describe/List/Delete/RestoreSecret, version stages, GetRandomPassword |
| SSM | Parameter Store: Put/Get/GetParameters(ByPath)/Delete/DescribeParameters, SecureString |
| KMS | Keys, aliases, Encrypt/Decrypt with encryption context, GenerateDataKey, enable/disable, scheduled deletion (local obfuscation, not real crypto) |
| CloudWatch Logs | Groups, streams, PutLogEvents, GetLogEvents, FilterLogEvents (plain terms), retention |
| Lambda | python* / nodejs* functions run as local processes; Invoke (sync, Event, DryRun, log tail), timeouts, errors, env vars, execution-role credentials, SQS event source mappings, logs to CloudWatch Logs |
| EventBridge | Buses, rules (event patterns incl. prefix/numeric/exists/anything-but, rate() schedules), SQS/SNS/Lambda targets, Input/InputPath |
| EC2 (network) | VPCs, subnets, internet gateways, route tables, security groups, instances (records only), DescribeAvailabilityZones |

## IAM enforcement

Every request is evaluated against the caller's identity policies (Allow/Deny, wildcards, NotAction/NotResource,
String/Arn/Bool conditions). Unregistered access keys (e.g. `test`) act as the account root and are always allowed.
With `ENFORCE_IAM=1` denied requests fail like the real service; without it the decision and its reason only
appear in the event stream and GUI.

Unsupported S3 sub-resources answer `501 NotImplemented`. State lives in memory only for now.

## Integrations

S3 bucket notifications → SQS / SNS / Lambda (prefix/suffix filters), SNS → SQS / Lambda, SQS → Lambda,
EventBridge → SQS / SNS / Lambda. Every hop shows up in the event stream.

## Chaos

`POST /_admin/chaos` (header `x-rocalcloud`) with
`{"rules": [{"service": "dynamodb", "op": "Get*", "latency_ms": 200, "error_rate": 0.1, "throttle_rate": 0.2}]}`
injects latency, 500s and service-specific throttling errors. `{"rules": []}` turns it off.

## Built-in endpoints

- `GET /_events` — Server-Sent Events, one JSON event per request
- `GET /_ui` — GUI page
- `GET /_admin/state`, `POST /_admin/reset` (needs header `x-rocalcloud`)
- `GET /_admin/reach?from=internet|<instance-id>&to=...&protocol=tcp&port=443` — step-by-step reachability
  (route table → internet gateway, public IP, security group rules). NACLs, peering and NAT are not modeled yet.

## License

Apache-2.0
