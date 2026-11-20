# rocalcloud

A local, in-memory emulator for the cloud APIs your app actually uses. Point an official SDK at
`http://127.0.0.1:4566` and it works offline. Plan and roadmap: [local-cloud-emulator-plan.md](local-cloud-emulator-plan.md).

## Run

```sh
cd core && cargo run --release        # emulator on 127.0.0.1:4566 (BIND, REGION env vars)
cd gui && cargo run                   # desktop window (Tauri), or open http://127.0.0.1:4566/_ui
uv run --with boto3 tests/sdk_test.py # official-SDK compatibility check
```

## Supported

| Service | Operations |
|---|---|
| DynamoDB | Create/Describe/List/DeleteTable, Put/Get/Update/DeleteItem, Query, Scan, BatchWrite/GetItem, TransactWrite/GetItems, GSI/LSI, condition/filter/update/projection expressions |
| S3 | List/Create/Head/DeleteBucket, Put/Get/Head/Delete/CopyObject, Range, ListObjects(V2) with prefix/delimiter/paging, DeleteObjects, multipart upload, presigned URLs |
| SQS | Create/Delete/List/PurgeQueue, GetQueueUrl, Get/SetQueueAttributes, Send/Receive/DeleteMessage (+Batch), ChangeMessageVisibility, long polling, dead-letter queues |

Unsupported S3 sub-resources answer `501 NotImplemented`. State lives in memory only for now.

## Built-in endpoints

- `GET /_events` — Server-Sent Events, one JSON event per request
- `GET /_ui` — GUI page
- `GET /_admin/state`, `POST /_admin/reset` (needs header `x-rocalcloud`)

## License

Apache-2.0
