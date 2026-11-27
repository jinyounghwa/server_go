# rocalcloud

A fast, deterministic, single-binary local cloud emulator written in Rust. Point your official cloud SDKs (Python, JavaScript, Rust, etc.) at `http://127.0.0.1:4566` and develop, test, and debug completely offline—complete with a built-in web/desktop GUI, a real-time 3D Character Town visualizer, chaos engineering, and optional local LLM explanation & verification agents.

> **Architecture & Project Roadmap:** See [local-cloud-emulator-plan.md](local-cloud-emulator-plan.md) for the full design principles, system architecture, and implementation checklist.

---

## Architecture Overview

```text
[Official SDKs / App Code]  ──►  http://127.0.0.1:4566
                                       │
                        ┌──────────────▼──────────────┐
                        │   rocalcloud (Rust binary)  │
                        │  • SigV4 + IAM Policy Engine│
                        │  • Chaos Fault Injector     │
                        │  • 22+ Cloud Service Modules│
                        │  • In-Memory + JSON Snapshot│
                        └──────────────┬──────────────┘
                                       │ SSE (/_events)
             ┌─────────────────────────┼─────────────────────────┐
             ▼                         ▼                         ▼
     Desktop / Web GUI        3D Character Town         Local LLM Agents
    (Tauri / /_ui)         (/_town & GitHub Pages)    (Explain & Inspector)
```

---

## Quick Start

### Run from source

```sh
cd core && cargo run --release                  # starts emulator on http://127.0.0.1:4566
ENFORCE_IAM=1 cargo run --release               # enable strict IAM policy enforcement
ENFORCE_IAM=1 VERIFY_SIGV4=1 cargo run --release # also verify SigV4 request signatures
RC_CONFIG=rocalcloud.env cargo run --release    # load settings from a KEY=VALUE file (env vars win)
```

Open the built-in web interfaces in your browser:
- **Management GUI:** `http://127.0.0.1:4566/_ui` (or run `cd gui && cargo run` for the Tauri desktop window)
- **3D Character Town:** `http://127.0.0.1:4566/_town`

### Run with Docker

```sh
docker build -t rocalcloud .
docker run --rm -p 127.0.0.1:4566:4566 -e ENFORCE_IAM=1 rocalcloud
```

### Prebuilt Binaries & Homebrew

- **GitHub Releases:** Pushing a `v*` tag builds macOS (`arm64` / `x86_64`) and Linux (`x86_64`) binaries with `SHA256SUMS` via [`.github/workflows/release.yml`](.github/workflows/release.yml).
- **Homebrew:** Formula is located at [`packaging/homebrew/rocalcloud.rb`](packaging/homebrew/rocalcloud.rb).

### Pointing an SDK at rocalcloud

Configure your SDK with endpoint `http://127.0.0.1:4566`, any region (default `us-east-1`), and credentials `test` / `test` (unregistered access keys act as the account root). For S3, use path-style addressing (`addressing_style="path"` in boto3, `forcePathStyle: true` in JS SDK v3).

---

## Configuration

All options can be set via environment variables or a `KEY=VALUE` file pointed to by `RC_CONFIG` (real environment variables always take precedence). Inspect active settings at `GET /_admin/config`.

| Variable | Default | Description |
|---|---|---|
| `BIND` | `127.0.0.1:4566` | HTTP listen address (keep `127.0.0.1` unless Docker containers need to call back) |
| `REGION` | `us-east-1` | Default region for ARNs and responses |
| `ENFORCE_IAM` | `0` | Set `1` to enforce IAM policy decisions (otherwise logged only) |
| `VERIFY_SIGV4` | `0` | Set `1` to verify SigV4 header and presigned query signatures |
| `STRICT_DELIVERY` | `0` | With `ENFORCE_IAM=1`, refuse SNS/EventBridge/S3 deliveries to targets with no resource policy (AWS behavior) |
| `RC_ROOT_SECRET` | `test` | Secret key used for unregistered (root) access keys when `VERIFY_SIGV4=1` |
| `RC_CONFIG` | *(unset)* | Path to a `KEY=VALUE` configuration file (`#` comments supported) |
| `RC_STATE_FILE` | *(unset)* | JSON snapshot file auto-loaded on startup and written via `POST /_admin/snapshot/save` |
| `RC_SQLITE_FILE` | `:memory:` | SQLite DB file for persistent service state, snapshot history, and event log (`/_admin/sqlite/*`, `/_admin/sql`) |
| `RC_TOWN_ORIGIN` | `https://jinyounghwa.github.io` | Single CORS origin allowed to read scrubbed `/_events` for GitHub Pages; set `off` to disable |
| `RC_LLM_URL` | `http://127.0.0.1:11434` | Local Ollama endpoint for the explanation and verification agents |
| `RC_LLM_MODEL` | `qwen3.5:9b` | Model name used by Ollama |
| `RC_DNS_PORT` | `10053` | Local UDP/TCP port (`127.0.0.1`) for the Route 53 DNS server |
| `RC_DOCKER` | `docker` | Docker CLI binary used by RDS, ElastiCache, and ECS |
| `RC_CONTAINER_MEMORY` | `512m` | Memory limit applied to each spawned Docker container |

---

## Supported Services

| Service | Emulated Operations & Features |
|---|---|
| **DynamoDB** | Create/Describe/List/DeleteTable, Put/Get/Update/DeleteItem, Query, Scan, BatchWrite/GetItem, TransactWrite/GetItems (positioned `CancellationReasons`, `ClientRequestToken` idempotency, one-op-per-item), GSI/LSI, condition/filter/update/projection expressions with nested `a.b[0]` document paths (same-index projections merge), exact decimal arithmetic for `ADD`/`SET a = a + :n` (38-digit limit on every N value, no f64 rounding), 400 KB item limit, DynamoDB Streams with all four `StreamViewType` record shapes (`dynamodbstreams` target, shard iterators, `KEYS_ONLY`/images) |
| **S3** | List/Create/Head/DeleteBucket, Put/Get/Head/Delete/CopyObject, Range reads, ListObjects(V2) with prefix/delimiter/paging, DeleteObjects, multipart upload, SigV4 presigned URLs |
| **SQS** | Create/Delete/List/PurgeQueue, GetQueueUrl, Get/SetQueueAttributes, Send/Receive/DeleteMessage (+Batch, per-message `DelaySeconds` 0–900s on standard queues, rejected on FIFO), ChangeMessageVisibility, long polling, DLQs, FIFO queues (`MessageGroupId` ordering, deduplication IDs & content-based dedup, 5-min window), 256 KiB message limit |
| **IAM / STS** | Users, roles, managed & inline policies, access keys, `SimulatePrincipalPolicy`, `AssumeRole` (trust policy checked, session credentials expire at `Expiration` with `ExpiredToken`), `GetCallerIdentity` |
| **SNS** | Topics (standard & FIFO `.fifo` topics with `MessageGroupId`, 5-min dedup / `ContentBasedDeduplication`, FIFO-SQS-only subscriptions), subscriptions (SQS, Lambda), filter policies (exact/prefix/suffix/anything-but/exists, numeric ranges), raw delivery, topic/subscription attributes |
| **Secrets Manager** | Create/Get/Put/Update/Describe/List/Delete/RestoreSecret, version stages, `GetRandomPassword` |
| **SSM** | Parameter Store: Put/Get/GetParameters(ByPath)/Delete/DescribeParameters, `SecureString` |
| **KMS** | Keys, aliases, Encrypt/Decrypt with encryption context, `GenerateDataKey`, enable/disable, scheduled deletion *(local obfuscation only, not real cryptography)* |
| **CloudWatch Logs** | Log groups, streams, `PutLogEvents`, `GetLogEvents`, `FilterLogEvents` (plain terms, `?OR` lists, JSON `{ $.a = "x" $.n != 2 }` patterns), retention |
| **Lambda** | `python*` / `nodejs*` functions run as local processes; `Invoke` (sync, Event with per-function destinations — OnSuccess/OnFailure, MaximumRetryAttempts, MaximumEventAgeInSeconds —, DryRun, log tail), timeouts, errors, env vars, execution-role credentials, versions (`PublishVersion`) and aliases (`fn:alias` / `Qualifier`), weighted alias routing (`AdditionalVersionWeights` → `ExecutedVersion`), per-qualifier event-invoke configs, SQS and Kinesis event source mappings (Kinesis: per-shard order, `TRIM_HORIZON`/`LATEST`, `MaximumRetryAttempts`, `BisectBatchOnFunctionError` with SQS/SNS on-failure destinations), logs to CloudWatch Logs |
| **EventBridge** | Buses, rules (event patterns incl. prefix/suffix/numeric/exists/anything-but, `rate()`/`cron()` schedules in UTC), SQS/SNS/Lambda targets, `Input`/`InputPath`/`InputTransformer`, per-target `RetryPolicy` & SQS `DeadLetterConfig`, Archives & Replays (`Create/Describe/List/DeleteArchive`, `Start/Describe/ListReplay` with `replay-name`) |
| **Step Functions** | ASL interpreter: Pass, Task (`lambda:invoke`, `sqs:sendMessage`, `sns:publish`, `dynamodb:*`), Choice, Wait, Succeed, Fail, Parallel, Map (concurrent with `MaxConcurrency`), Retry/Catch, Parameters/ResultSelector/ResultPath/OutputPath, extended JSONPath (`[*]`, `[-1]`, `['key']`, `$$` context), 18 intrinsics (`Format`, `StringToJson`, `JsonToString`, `Array*`, `Base64Encode`/`Decode`, `Hash`, `StringSplit`, `JsonMerge`, `MathAdd`/`Random`, `UUID`), execution history, `StopExecution`, `.waitForTaskToken` integrations (SQS/SNS/Lambda) with `SendTaskSuccess`/`SendTaskFailure`/`SendTaskHeartbeat`, Task `TimeoutSeconds`/`HeartbeatSeconds` → `States.Timeout` |
| **API Gateway (HTTP APIs)** | `apigatewayv2` APIs, Lambda proxy integrations (payload 2.0), JWT (local Cognito RS256) & Lambda `REQUEST` (simple response 2.0) authorizers, routes with `{params}` and `{proxy+}`, stages + stage variables, CORS configuration (preflight + response headers), `HTTP_PROXY` integrations to loopback targets; invoke at `/_api/{apiId}/[{stage}/]path` |
| **API Gateway (REST v1)** | `apigateway` REST APIs: resources/methods (resource tree with `{param}`/`{proxy+}`), `AWS_PROXY` (Lambda, v1 event shape) and `MOCK` integrations, method/integration responses, deployments as real snapshots (a stage serves the tree it was deployed with; edits stay invisible until redeploy), stages, authorizers (`COGNITO_USER_POOLS` local-pool JWTs, Lambda `TOKEN`/`REQUEST` with IAM policy parsing - explicit Deny wins, glob `Resource`s), API keys + usage plans (`x-api-key`, per-key token-bucket throttle - `rateLimit`/`burstLimit`, no quota counters), CFN types `AWS::ApiGateway::RestApi/Resource/Method/Deployment/Stage`; invoke at `/_restapi/{apiId}/{stage}/path`; AWS/HTTP integrations and VTL `requestTemplates` are rejected (not faked) |
| **Cognito** | User pools, app clients (with secrets), SignUp/Confirm, ForgotPassword, `USER_PASSWORD_AUTH`, refresh tokens, `NEW_PASSWORD_REQUIRED`, admin user APIs, groups (CRUD + membership, `cognito:groups` claim), Lambda triggers (`PreSignUp`, `PostConfirmation`, `PreTokenGeneration` claim overrides), RS256 JWTs with JWKS at `/_cognito/{poolId}/.well-known/jwks.json`; verification codes emit `CodeSent` events |
| **Kinesis** | Streams, shards (MD5 hash ranges), `PutRecord(s)`, shard iterators (`TRIM_HORIZON`, `LATEST`, `AT/AFTER_SEQUENCE_NUMBER`, `AT_TIMESTAMP`), `GetRecords` with retention-window trimming, `RetentionPeriodHours` (increase/decrease), resharding (`SplitShard`/`MergeShards`/`UpdateShardCount` UNIFORM_SCALING; closed shards stay readable) |
| **SES** | v1 (Query) and v2 (REST): identities, `SendEmail`, `SendRawEmail`; messages appear in the GUI mailbox and are never sent externally |
| **RDS** | `postgres` / `mysql` / `mariadb` instances as real Docker containers on `127.0.0.1`; create, describe, stop, start, reboot, delete; snapshots (docker commit, data outside image volumes via `PGDATA`/`--datadir`) with restore; parameter groups (whitelisted names, applied as `-ckey=value`/`--key=value` on (re)creation) |
| **ElastiCache** | `redis` / `valkey` / `memcached` clusters as Docker containers; create, describe (with node endpoints), delete |
| **ECS** | Clusters, task definitions (revisions), `RunTask`/`StopTask` as Docker containers with port mappings, env, overrides, task-role credentials, `awslogs` → CloudWatch Logs; services maintain `desiredCount` and register with ALB target groups |
| **ELB v2 (ALB)** | Load balancers, target groups, listeners bound to `127.0.0.1:{Port}` (>= 1024) with round-robin L4 forwarding to healthy targets, fixed responses, target health |
| **Route 53** | Hosted zones, record sets (`CREATE`/`UPSERT`/`DELETE`, aliases, wildcards), loopback TCP/HTTP health checks, routing policies (weighted, failover with health checks, latency), plus a local UDP/TCP DNS server on `127.0.0.1:10053` (`RC_DNS_PORT`, UDP >512B truncation with TC bit) answering `A`/`AAAA`/`CNAME`/`TXT` |
| **CloudFormation** | JSON/YAML templates (short tags), Parameters, Conditions, Mappings, `Ref`/`GetAtt`/`Sub`/`Join`/`Select`/`Split`/`If`/`FindInMap`/`GetAZs`/`Base64`, dependency ordering, Outputs with exports, `Fn::ImportValue`/`ListExports`/`ListImports` (imported exports block delete/change), in-place property updates (SQS attributes, Lambda env/memory/timeout, SNS DisplayName, DDB throughput) vs replacement, create/update/delete with rollback |
| **EC2 (Network)** | VPCs, subnets, internet gateways, route tables, security groups, instances (metadata records), `DescribeAvailabilityZones`, step-by-step reachability analysis at `/_admin/reach` |

Unsupported S3 sub-resources return `501 NotImplemented`, and unsupported operations return explicit errors (`UnknownOperationException`) instead of faking success.

---

## IAM Enforcement & Signature Verification

- **IAM (`ENFORCE_IAM=1`):** Every request is evaluated against the caller's identity policies (Allow/Deny, wildcards, `NotAction`/`NotResource`, `String`/`Arn`/`Bool`/`Numeric`/`Date`/`IpAddress` conditions with `IfExists` and `ForAnyValue`/`ForAllValues`, against request context keys such as `aws:SourceIp`, `aws:EpochTime`, `aws:CurrentTime`, `aws:RequestedRegion`). Unregistered access keys (e.g. `test`) act as account root and are always allowed. Without `ENFORCE_IAM=1`, decisions and denial reasons are recorded in the event stream and GUI without blocking requests.
- **SigV4 (`VERIFY_SIGV4=1`):** Every request (Authorization header and presigned query auth, including session tokens and expiry) must carry a valid SigV4 signature. Wrong secrets receive `SignatureDoesNotMatch` / `InvalidSignatureException`; unsigned requests receive `MissingAuthenticationToken` (Cognito public operations remain unsigned). SigV2 presigned URLs are refused with a clear error; presign with `signature_version="s3v4"`. Header-signed requests whose `x-amz-date` is more than 15 minutes off are refused with `RequestTimeTooSkewed` (presigned URLs keep only their `X-Amz-Expires`). `aws-chunked` bodies are verified against their declared payload hash (individual chunk signatures are not verified).

---

## Integrations, Chaos & Docker-Backed Services

- **Event-Driven Integrations:** S3 bucket notifications → SQS / SNS / Lambda (with prefix/suffix filters; destinations validated on save), SNS → SQS / Lambda, SQS → Lambda, EventBridge → SQS / SNS / Lambda. Every hop is emitted to `/_events`.
- **Chaos Injection:** `POST /_admin/chaos` (requires header `x-rocalcloud: 1`) injects latency, HTTP 500s, and service-specific throttling:
  ```json
  {"rules": [{"service": "dynamodb", "op": "Get*", "latency_ms": 200, "error_rate": 0.1, "throttle_rate": 0.2}]}
  ```
  Send `{"rules": []}` to disable chaos rules.
- **Docker-Backed Services:** RDS, ElastiCache, and ECS manage containers via the `docker` CLI (`RC_DOCKER`). Every container publishes ports on `127.0.0.1` only and is capped at `RC_CONTAINER_MEMORY` (default `512m`) and 1 CPU. Leftover `rocalcloud-*` containers are cleaned up at startup and on `/_admin/reset`.

---

## 3D Character Town (`/_town` & GitHub Pages)

`/_town` visualizes the live event stream as a 3D coastal city: every request drives a delivery van past the IAM checkpoint gate to its service's building, service-to-service deliveries fly as glowing parabolic drones between rooftops, and outcomes appear as `✓` / `!` / `✗` / `✋` / `⚡` / `🛡` / `⚠` alongside a live text feed.

- **Hosted Demo / Live Viewer:** [https://jinyounghwa.github.io/server_go/](https://jinyounghwa.github.io/server_go/) automatically connects to a local `rocalcloud` instance on `http://127.0.0.1:4566` (or another loopback port via `?api=http://127.0.0.1:<port>`). Until a local instance responds, it runs scripted mock traffic and retries every 5 seconds. Append `?demo` to force mock traffic.

---

## Security Model

rocalcloud is designed for local development and takes defense-in-depth precautions so browsing external websites cannot tamper with or exfiltrate your local emulator state:

1. **Loopback Binding by Default:** HTTP (`127.0.0.1:4566`), DNS (`127.0.0.1:10053`), ALB listeners, and all Docker container port mappings bind strictly to `127.0.0.1`.
2. **CSRF Protection on Mutating Endpoints:** All state-mutating `POST` endpoints (`/_admin/reset`, `/_admin/chaos`, `/_admin/snapshot`, `/_admin/snapshot/save`, `/_agent/*`, `/_inspect/*`) require the custom `x-rocalcloud` header, forcing a CORS preflight that fails for cross-origin pages.
3. **GitHub Pages Character Town Hardening:**
   - **Single-Origin CORS + `Vary: Origin`:** Only the exact origin in `RC_TOWN_ORIGIN` (default `https://jinyounghwa.github.io`) receives `Access-Control-Allow-Origin` on `GET /_events`. Set `RC_TOWN_ORIGIN=off` to disable cross-origin streaming completely.
   - **Allowlist Event Scrubbing (`town_view`):** Cross-origin `/_events` streams only forward minimal visualization fields (`ts`, `service`, `op`, `status`, `trigger`, `protocol`, `target`, inspector summary, `auth.decision/enforced`, `chaos.fault`). Sensitive fields—including Cognito confirmation `code`, IAM `principal` ARNs, `request_id`, detailed `error` payloads, IAM policy `auth.reason`, and chaos `rules`—are stripped before leaving the process.
   - **Shared `*.github.io` Origin Caveat:** All repositories published under the same GitHub user account share the single `https://<user>.github.io` origin. If you host untrusted content on another repository under the same GitHub Pages account, or want zero cross-origin exposure, set `RC_TOWN_ORIGIN=off` and use the local `http://127.0.0.1:4566/_town` instead.
   - **Client-Side `?api=` Loopback Validation & CSP:** `town.html` strictly restricts `?api=` to `http:`/`https:` URLs on loopback hosts (`127.0.0.1`, `localhost`; IPv6 `[::1]` is rejected because CSP cannot list it) to prevent `javascript:` URI XSS and phishing redirects. It also ships with a strict `<meta>` Content-Security-Policy (`connect-src` limited to loopback + `https://esm.sh`) and `referrer="no-referrer"`.
   - **Third-Party CDN Tradeoff:** The 3D scene loads Three.js (`0.170.0`) from `https://esm.sh` via import map. For air-gapped or zero-CDN environments, use the self-contained local `/_ui` dashboard (which has zero external asset dependencies) and set `RC_TOWN_ORIGIN=off`.

---

## Explanation & Verification Agents

### Explanation Agent
- `POST /_agent/explain {"request_id": ...}` returns a deterministic rule-based explanation for any failed or denied request. When Ollama is reachable at `RC_LLM_URL` (default `http://127.0.0.1:11434`, model `RC_LLM_MODEL`), a concise natural-language explanation is added.
- `POST /_agent/ask {"question": ...}` answers using four schema-constrained tools (list resources, recent events, explain event, call JSON API). Destructive actions return a confirmation token and execute only when resubmitted with `{"confirm": "<token>"}`.
- `GET /_agent/template` drafts a CloudFormation YAML template from current S3, DynamoDB, SQS, SNS, and SSM resources.
- LLM calls are serialized and paced at least 1.5 s apart. For a remote Ollama host, tunnel over SSH: `ssh -f -N -L 11434:127.0.0.1:11434 <host>`.

### Verification Agent (Inspector)
- `POST /_inspect/run` (header `x-rocalcloud: 1`) executes 20 deterministic security, chaos, incident, performance, and fuzzing scenarios strictly against `127.0.0.1` (auto-signing its own requests so it works with or without `VERIFY_SIGV4=1`).
- Pass `{"use_llm": true}` to let the local LLM propose additional non-destructive scenarios (still executed and judged deterministically).
- Export reports via `GET /_inspect/report/{id}?format=md` or `?format=html`, save regressions to `tests/regressions/*.json`, and replay single scenarios via `POST /_inspect/replay`.

---

## Compatibility Test Suites (Python · JS · Rust)

Start the server with `ENFORCE_IAM=1` (and optionally `VERIFY_SIGV4=1`), then run any of the official SDK suites:

```sh
# Rust unit tests (must compile with 0 warnings)
cd core && cargo test

# Python (boto3) — full integration suite
uv run --with boto3 --with "pyjwt[crypto]" --with pg8000 --with pymysql --with redis --with dnspython tests/sdk_test.py

# JavaScript (@aws-sdk v3)
cd tests/js && npm install && npm test

# Rust (aws-sdk-rust)
cd tests/rust && cargo run
```

## Diagnostic & DB Query Tools (`tools/`)

```sh
# Unified DB query CLI (SQLite / DynamoDB / RDS / Redis)
uv run --with boto3 tools/db_query.py sqlite "SELECT service, count(*) FROM events GROUP BY service"
uv run --with boto3 tools/db_query.py ddb tables
uv run --with boto3 --with pg8000 --with pymysql tools/db_query.py rds list
uv run --with boto3 --with redis tools/db_query.py redis list

# Cross-SDK response auto-comparison (Python boto3 vs JS @aws-sdk v3)
uv run --with boto3 tools/sdk_compare.py

# Partial failure & chaos recovery diagnostic
uv run --with boto3 tools/partial_fail_check.py --rates 0.2,0.5 --samples 60

# Process RSS memory growth & throughput benchmark
uv run --with boto3 tools/mem_bench.py --cycles 300 --payload-kb 4
```

---

## Built-in Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /_events` | Server-Sent Events stream (one JSON event per request; allowlist-scrubbed for `RC_TOWN_ORIGIN`) |
| `GET /_ui` | Built-in web GUI (resource explorer, live log, explanation agent, inspector, settings) |
| `GET /_town` | Real-time 3D Character Town visualizer |
| `GET /_admin/config` | Active startup configuration and flags |
| `GET /_admin/state` | Current resource summaries across all 22+ services |
| `GET /_admin/snapshot` / `POST /_admin/snapshot` | Export or restore JSON state snapshots (`POST` requires `x-rocalcloud`) |
| `POST /_admin/snapshot/save` | Persist current state to `RC_STATE_FILE` (requires `x-rocalcloud`) |
| `GET /_admin/sqlite/snapshots`, `POST /_admin/sqlite/save`, `POST /_admin/sqlite/restore` | List, save, and restore SQLite-backed state snapshots (`POST` requires `x-rocalcloud`) |
| `POST /_admin/sql` | Execute read-only `SELECT` / `WITH` / `PRAGMA table_info` SQL queries on the SQLite store (requires `x-rocalcloud`) |
| `POST /_admin/reset` | Wipe all in-memory state and clean up Docker containers (requires `x-rocalcloud`) |
| `GET /_admin/chaos` / `POST /_admin/chaos` | Inspect or configure chaos fault injection rules (`POST` requires `x-rocalcloud`) |
| `GET /_admin/reach` | Step-by-step VPC reachability check (`?from=internet\|<id>&to=...&protocol=tcp&port=443`) |
| `GET /_agent/status`, `POST /_agent/explain`, `POST /_agent/ask`, `GET /_agent/template` | Explanation agent endpoints |
| `POST /_inspect/run`, `GET /_inspect/reports`, `GET /_inspect/report/{id}`, `POST /_inspect/replay` | Verification agent (inspector) endpoints |

---

## Known Limitations

- State is held in memory (persistable via JSON snapshots `RC_STATE_FILE`; no SQLite backend yet).
- Resource-based policies (e.g. S3 bucket policies) are not evaluated yet (identity policies are).
- KMS uses local obfuscation rather than production cryptography.
- ALB operates at L4 (round-robin TCP forwarding without HTTP path/host routing rules).
- Step Functions `Parallel` branches execute sequentially.
- Deliberate shortcuts are marked with `// ponytail:` comments across `core/src/`.

## Documentation

- [Project Plan & Architecture Roadmap](local-cloud-emulator-plan.md) — design principles, architecture, and full implementation checklist
- [Contributing Guide](CONTRIBUTING.md) — development rules, how to add a service, and running test suites
- [Agent Skill Guide](SKILL.md) — quick reference for AI coding agents using `rocalcloud`

## License

Apache-2.0 — see [LICENSE](LICENSE).
