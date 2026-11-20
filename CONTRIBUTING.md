# Contributing to rocalcloud

Thank you for your interest in contributing to **rocalcloud**!

## Design principles

1. **Deterministic core**: Keep all service emulation deterministic. Local LLMs live only outside the core (`agent.rs`, optional scenario proposals in `inspector.rs`), and everything must work with the LLM disabled.
2. **Minimal dependencies**: Prefer the Rust standard library and crates already in `core/Cargo.toml`. Keep compiler warnings at 0.
3. **Honest boundaries**: Never fake unsupported features — return explicit errors (`501 NotImplemented`, `UnknownOperationException`, etc.) and document deliberate shortcuts with `// ponytail:` comments.
4. **Loopback-by-default security**: Bind to `127.0.0.1` by default, do not enable permissive CORS on `/_events`, and require the `x-rocalcloud` header on all state-mutating admin/agent/inspector `POST` endpoints.
5. **Naming**: Do not use trademarked cloud provider names in the project, package, or binary names.

## Adding or extending a service

1. Implement state, `handle(...)`, and `admin()` (returning `{name, count, sub, cols, rows}` for the generic GUI table) in `core/src/<svc>.rs`.
2. Wire it in `core/src/main.rs`: `mod <svc>;`, `App` field, `reset()`, `state()`, routing/protocol match, and `checks()` for IAM authorization.
3. Register the service in `core/src/ui.html` (`GENERIC`) and `core/src/town.html` (building `svc` list).
4. Add integration tests covering both happy paths and error paths in `tests/sdk_test.py` (and optionally `tests/js/` or `tests/rust/`).

## Running tests

```sh
# 1. Rust unit tests (0 warnings)
cd core && cargo test && cargo build --release

# 2. Start the server with IAM enforcement enabled
ENFORCE_IAM=1 ./core/target/release/rocalcloud

# 3. Python (boto3) compatibility suite
uv run --with boto3 --with "pyjwt[crypto]" --with pg8000 --with pymysql --with redis --with dnspython tests/sdk_test.py

# 4. JavaScript (@aws-sdk v3) compatibility suite
cd tests/js && npm install && npm test

# 5. Rust (aws-sdk-rust) compatibility suite
cd tests/rust && cargo run
```

## License

Contributions are licensed under Apache-2.0 (see [LICENSE](LICENSE)).
