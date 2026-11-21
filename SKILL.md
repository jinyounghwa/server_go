---
name: rocalcloud
description: Run application code and official AWS SDKs against the local rocalcloud emulator instead of a real cloud account. Use when testing code that calls DynamoDB, S3, SQS, SNS, Lambda, IAM and the other services listed in README.md, or when checking IAM policies, chaos behaviour or reachability locally.
---

# rocalcloud 사용법 (에이전트용)

## 띄우기
```sh
cd core && ENFORCE_IAM=1 cargo run --release        # 127.0.0.1:4566
# 서명까지 검증하려면 VERIFY_SIGV4=1, 설정 파일은 RC_CONFIG=파일(KEY=VALUE)
```
준비 확인: `curl -sf http://127.0.0.1:4566/_admin/state`

## SDK 연결
- 엔드포인트 `http://127.0.0.1:4566`, 리전 `us-east-1`, 키 `test`/`test`(등록 안 된 키는 루트).
- S3는 path-style을 쓴다(boto3 `Config(s3={"addressing_style": "path"})`, JS `forcePathStyle: true`).
- 사전 서명 URL은 `signature_version="s3v4"`로 만든다.

## 결과 확인
- 실시간 이벤트: `GET /_events`(SSE). 모든 요청이 `{service, op, status, auth, error}`로 나온다.
- 상태: `GET /_admin/state`, 초기화: `POST /_admin/reset`(헤더 `x-rocalcloud: 1`).
- 거부 이유: 이벤트의 `auth.reason` 또는 `POST /_agent/explain {"request_id": ...}`.

## 장애·검사
- 장애 주입: `POST /_admin/chaos {"rules": [...]}`(헤더 필수), 해제는 `{"rules": []}`.
- 자체 검사: `POST /_inspect/run {}`(헤더 필수). 실패는 `results[].repro`로 재현.

## 하지 말 것
- 상태는 기본 인메모리다. 남기려면 `RC_STATE_FILE`+`POST /_admin/snapshot/save` 또는 `RC_SQLITE_FILE`+`POST /_admin/sqlite/save`.
- 지원하지 않는 API는 `UnknownOperationException`/501로 답한다. 흉내 낸 응답을 기대하지 말 것.
- **맥 경량화 유지**: 맥에 `core/target`, `tests/rust/target`, `gui/target`, `tests/js/node_modules`를 남겨 두지 않는다. 무거운 빌드·테스트·Docker 검증은 우분투(`ubuntu:~/work/projects/rocalcloud/`, `tools/ubuntu_verify.sh`)에서 실행한다.
