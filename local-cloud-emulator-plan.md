# Local Cloud Emulator — Project Plan & Architecture Roadmap

> **Goal:** Emulate the full cloud backend stack needed by real applications completely offline on a local machine, paired with a desktop GUI, a 3D real-time character town, and local LLM explanation & verification agents.
>
> **Created:** 2026-11-20 · **Last Updated:** 2026-11-21 · **Overview & Quick Start:** [README.md](README.md)

---

## 1. Key Design Decisions

| Area | Decision |
|---|---|
| Implementation Model | Sprint-based development, gated by official SDK compatibility suites |
| Runtime Agents | Local 7B–9B quantized LLM (Q4/Q5 via Ollama), strictly outside the core |
| Core Runtime | Rust single binary (`axum`, `tokio`, `serde_json`, `serde_yaml`, `sha2`, `rsa`, etc.) |
| Desktop GUI | Tauri 2 shell wrapping the built-in `/_ui` web application |
| Character Town | Real-time 3D interactive city (Three.js + SSE `/_events`) |
| Licensing | Open source (Apache-2.0), non-commercial |
| Scope Strategy | Implement APIs actually used by real projects first; expand incrementally rather than faking unimplemented features |
| Naming | `rocalcloud` — avoids trademarked cloud provider names |

## 2. Core Design Principles

- **Deterministic Core:** All service emulation logic is strictly deterministic. Local LLMs live exclusively outside the core (`agent.rs`, optional scenario proposals in `inspector.rs`).
- **Graceful Fallback Without LLM:** Every feature must work when no LLM is running. Rule-based explanation templates and deterministic inspector scenarios run first; LLM output is layered on top.
- **Minimal, Constrained Agent Tools:** Agents interact with the emulator through a small, well-defined tool surface with schema-constrained output so smaller local models remain reliable.
- **Unified Event Bus:** Every API request, service-to-service delivery, IAM decision, chaos fault, and inspector action is published to a single event stream (`/_events`) consumed by the GUI, 3D Character Town, and agents.
- **Official SDK Gates:** Every sprint is verified against official SDK integration tests (Python `boto3`, JavaScript `@aws-sdk` v3, Rust `aws-sdk-rust`) with `ENFORCE_IAM=1` and `VERIFY_SIGV4=1`.
- **Loopback-by-Default Security:** All services and Docker containers bind to `127.0.0.1` by default; mutating admin endpoints require a custom `x-rocalcloud` header; cross-origin access to `/_events` is limited to a single configured origin (`RC_TOWN_ORIGIN`) with allowlist-scrubbed payloads.

## 3. System Architecture

```text
[Official Cloud SDKs / Application Code]
        │ HTTP (only the endpoint URL changes to http://127.0.0.1:4566)
        ▼
[Core Runtime (Rust single binary)] ──► [In-Memory State + JSON Snapshots (RC_STATE_FILE)]
   │  Protocol layer: AWS JSON / REST-XML / Query + optional SigV4 verification
   │  IAM policy evaluator & chaos fault injector
   │  22+ service modules (Docker-backed for RDS, ElastiCache, ECS)
   │  Unified Event Bus (SSE /_events + recent ring buffer)
   ├──► [Desktop GUI (Tauri / /_ui)]
   ├──► [3D Character Town (Three.js / /_town & GitHub Pages)]
   ├──► [Explanation Agent (rule-based + local Ollama LLM)]
   └──► [Verification Agent / Inspector (deterministic security, chaos, fuzz, perf)]
```

---

## 4. Implementation Checklist

Status as of **2026-11-21**: `[x]` completed, `[~]` partially implemented or intentionally replaced by an alternative (with rationale).

### 0. Foundation
- [x] Project name (`rocalcloud`, free of cloud provider trademarks)
- [x] License (`Apache-2.0`)
- [x] Supported services & API scope matrix (documented in [README.md](README.md))
- [x] Repository layout (`core/`, `gui/`, `tests/`, `packaging/`) — services, web UI, town, and agents compiled into the single `core` binary
- [x] Agent & contributor docs (`CLAUDE.md`, `SKILL.md`, `AGENTS.md`, `CONTRIBUTING.md`)
- [x] Sprint quality gates — CI runs Rust unit tests + Python & JS SDK suites under both default and `VERIFY_SIGV4=1` modes
- [x] CI / Release / Pages GitHub Actions workflows

### 1. Core Runtime (Rust)
- [x] HTTP server (`axum`, `tokio`)
- [x] Protocol adapters (AWS JSON 1.0/1.1, REST-XML, Query)
- [x] Service identification and routing (headers, host, path, query action/version)
- [x] SigV4 header parsing & optional full signature verification (`VERIFY_SIGV4=1`)
- [x] Account, region, and ARN model
- [x] State persistence (SQLite, memory mode, snapshots, reset) — In-memory state + JSON snapshots (`RC_STATE_FILE`, `/_admin/snapshot`) + bundled SQLite store (`RC_SQLITE_FILE`, `service_state` / `snapshots` / `events` tables, `/_admin/sqlite/*`, read-only SQL console at `/_admin/sql`)
- [x] Standard error formatting and request IDs (`x-amzn-requestid`, `x-amz-request-id`)
- [x] Event bus (publishes every request to SSE `/_events` and recent ring buffer)
- [x] Config file and environment variables (`RC_CONFIG` `KEY=VALUE`, `/_admin/config`)

### 2. Tier-1 Services
- [x] DynamoDB (tables, items, Query, Scan, GSI/LSI, batch & transactions, 400 KB item limit)
- [x] S3 (buckets, objects, range reads, multipart uploads, presigned URLs, bucket policies evaluated with identity policies)
- [x] SQS (standard & FIFO queues with `MessageGroupId` ordering and 5-minute deduplication, DLQ, visibility timeout, long polling, message attributes with MD5)
- [x] SNS (topics, SQS/Lambda subscriptions, filter policies, raw delivery)
- [x] Secrets Manager
- [x] SSM Parameter Store
- [x] KMS (keys, aliases, Encrypt/Decrypt with encryption context, GenerateDataKey — local obfuscation, not production cryptography)
- [x] CloudWatch Logs

### 3. Tier-2 Services
- [x] API Gateway (HTTP APIs v2, Lambda proxy 2.0, routes & stages)
- [x] Lambda (local `python*` / `nodejs*` process execution, timeouts, env vars, SQS triggers, CloudWatch Logs)
- [x] EventBridge (buses, pattern matching rules, `rate()`·`cron()` schedules, targets with Input/InputPath/InputTransformer)
- [x] Step Functions (ASL interpreter with Pass, Task, Choice, Wait, Succeed, Fail, Parallel, Map, Retry/Catch, intrinsics)
- [x] Cognito (user pools, app clients, auth flows, RS256 JWTs + JWKS endpoint)
- [x] SES (v1 Query & v2 REST, local GUI mailbox capture)
- [x] Kinesis (streams, MD5 shard hash ranges, iterators, GetRecords)
- [x] CloudFormation (JSON/YAML templates, intrinsics, dependency ordering, create/update/delete with rollback)

### 4. Virtualized Infrastructure Services
- [x] IAM & STS (users, roles, managed & inline policies, access keys, policy evaluator, `SimulatePrincipalPolicy`, `AssumeRole`, denial explanations)
- [x] EC2 / VPC Networking (VPCs, subnets, IGWs, route tables, security groups, graph-based reachability analyzer at `/_admin/reach`)
- [x] RDS (real Postgres / MySQL / MariaDB Docker containers bound to `127.0.0.1`)
- [x] ECS / EC2 (ECS tasks run as real Docker containers with ALB registration & `awslogs`; EC2 instances tracked as metadata records)
- [x] ElastiCache (real Redis / Valkey / Memcached Docker containers)
- [x] ELB v2 / ALB (real local TCP listeners on `127.0.0.1:{Port}` with round-robin forwarding, target health and path/host listener rules)
- [x] Route 53 (hosted zones, record sets, built-in local UDP DNS server on `127.0.0.1:10053`)

### 5. Cross-Service Integrations & Chaos Engineering
- [x] S3 bucket notifications → SQS, SNS, Lambda
- [x] SQS·Kinesis → Lambda event source mappings; SNS & EventBridge → SQS / SNS / Lambda
- [x] Chaos fault injection (`/_admin/chaos`: latency, 5xx errors, service-specific throttling)

### 6. Desktop & Web GUI (Tauri + `/_ui`)
- [x] Resource explorer (tables, buckets, queues, IAM, mail, etc.)
- [x] Real-time request & event log
- [x] IAM policy visualization and VPC reachability/network view
- [x] Snapshot export/restore, full state reset, and configuration/chaos settings panel

### 7. 3D Character Town (`/_town` & GitHub Pages)
- [x] Real-time event stream — implemented with SSE (`/_events`) instead of WebSocket
- [x] 3D Three.js coastal city with distinct architectural buildings per service group (warehouse, archive, post office, broadcast tower, workshop, factory, identity office, vault, container harbor, radar tower, construction crane)
- [x] Request-to-animation mapping (delivery vans, parabolic service-to-service drones, IAM checkpoint gate & guard, inspector patrols)
- [x] Outcome visual cues (success `✓`, 4xx `!`, 5xx `✗`, IAM deny `✋`, chaos `⚡`, inspector defend `🛡` / breach `⚠`)
- [x] Static demo deployment via GitHub Pages (replaced Netlify) — automatically connects to a visitor's local emulator (`127.0.0.1:4566` or loopback `?api=`) and falls back to mock traffic until connected, hardened with allowlist event scrubbing, loopback-only `?api=` validation, and strict CSP

### 8. Local LLM Explanation Agent
- [x] Runtime selection (Ollama)
- [x] Model selection & hardware benchmarking (`qwen3.5:9b` tested on RTX 3060 12 GB within 6.5 GB VRAM & thermal guard)
- [x] JSON schema / grammar-constrained tool output
- [x] Compact 4-tool set (list resources, inspect recent events, explain event, invoke JSON API)
- [x] Rule-based fallback explanations when LLM is unavailable
- [x] Confirmation-token workflow for destructive operations
- [x] Capabilities: natural-language Q&A / API calls, error & IAM denial explanation, CloudFormation YAML draft generation

### 9. Quality, Packaging & Release
- [x] Official SDK compatibility test suites (Python `boto3`, JS `@aws-sdk` v3, Rust `aws-sdk-rust`)
- [x] Fuzzing, property-based tests (`sigv4.rs`), throughput & memory benchmarks
- [x] Security hardening (loopback binding, CSRF header enforcement, GitHub Pages CORS/CSP/scrubbing)
- [x] Packaging (macOS & Linux release binaries, Homebrew formula, Dockerfile)
- [x] Documentation (`README.md`, API support matrix, `CONTRIBUTING.md`, `SKILL.md`)
- [x] Name & trademark sanity check (no conflicting product found as of 2026-11-21)
- [x] Initial public release (`v0.1.0`)

### 10. Verification Agent (Inspector — `inspector.rs`)

**Role:** Continuously probes and fault-tests the local emulator, visualizing attacks and defenses in the GUI and 3D town. The local LLM may optionally propose non-destructive scenarios, while all execution and pass/fail verdicts are strictly deterministic.

**Test Categories (20 built-in scenarios)**
- [x] **Security (8):** IAM implicit/explicit deny, bucket policy Deny binding root without lockout, CSRF header enforcement, S3 path traversal, missing/malformed SigV4, >256 MiB payload rejection (413), injection payloads
- [x] **Incidents (4):** 1000-message queue flood, DynamoDB 400 KB item & SQS 256 KiB message limits, Lambda repeated failures, SQS DLQ buildup
- [x] **Chaos / Fault Injection (6):** Throttling recovery, 5xx recovery, latency injection, 50% partial failure, mid-request dropped connections, table delete/recreate under write load
- [x] **Cross-SDK Compatibility:** Python, JS, and Rust suites verify overlapping services, and `tools/sdk_compare.py` runs identical 7-service scenarios on Python (`boto3`) and JS (`@aws-sdk` v3) to automatically diff normalized responses and error codes.
- [x] **Regression:** Failed scenarios can be saved to `tests/regressions/*.json` and replayed via `/_inspect/replay`
- [x] **Performance (2):** 40-request concurrent burst throughput, resident-memory growth across 2000 write/delete cycles
- [x] **Fuzzing (1):** 15 malformed inputs to detect panics or crashes

**Agent Architecture & UI**
- [x] Optional LLM scenario proposer (`{"use_llm": true}`)
- [x] Deterministic runner locked strictly to `127.0.0.1` (no external network access)
- [x] Rule-based verdict engine (independent of LLM)
- [x] Severity-sorted reporter with reproducible request payloads (`repro`)
- [x] Safety guardrails: loopback-only target check, `rc-insp-` resource prefix for destructive tests, iteration & time caps
- [x] GUI test runner, Markdown/HTML report export (`/_inspect/report/{id}?format=md|html`), run history, and 3D town inspector patrol animations

---

## 5. Local LLM Operations Notes (7B–9B Class)

- **Footprint:** On an RTX 3060 12 GB, a 7B–9B Q4/Q5 model uses ~5–6.5 GB VRAM and generates 30+ tokens/sec.
- **Strengths:** 1–3 sentence error/IAM explanations, selecting among a small set of tools, template-guided scenario generation.
- **Limitations & Mitigations:** Unstable tool call syntax (mitigated with schema-constrained output), long-context drift (mitigated by keeping prompts short), complex multi-file coding (handled by development-time agents, not runtime LLM).
- **Concurrency:** A single model instance is shared by the explanation agent and inspector; requests are serialized and spaced at least 1.5 s apart.

## 6. Recommended Sprint Order (Completed)

1. Core runtime + DynamoDB, S3, SQS (Rust)
2. Event stream + GUI (Tauri / `/_ui`)
3. IAM policy engine & VPC network reachability model
4. Remaining services added iteratively by project need
5. 3D Character Town (`/_town` + GitHub Pages)
6. Local LLM explanation agent
7. Verification agent (inspector)
8. Multi-SDK compatibility suites, packaging, security hardening & public release

Each stage was structured as an independent sprint so the emulator remained usable at every milestone.
