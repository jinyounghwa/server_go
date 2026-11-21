# rocalcloud — 인수인계 지침 (2026-11-21)

다음 작업자(모델)가 바로 이어서 코딩할 수 있도록 현재 상태, 규칙, 남은 일을 정리한 문서다.
계획 원본은 `local-cloud-emulator-plan.md`. 이 문서와 충돌하면 계획서가 목표, 이 문서가 현재 사실이다.

## 1. 현재 상태

- 계획서 4장 체크리스트를 실제 상태로 표시했다(2026-11-21). 6장 순서 **1~8단계 전부 완료** (코어·22개 서비스·GUI·캐릭터 마을·해설 에이전트·검증 에이전트·Python/JS/Rust 3개 SDK 호환성 스위트·Dockerfile/Homebrew/GitHub Actions CI·Release 패키징·문서 정비).
- 2026-11-21 추가: S3 버킷 정책·SQS 큐 정책(`Policy` 속성, Put/Get/DeleteBucketPolicy, 같은 계정 규칙: 명시적 Deny 우선, 신원·버킷 정책 중 하나의 Allow면 허용, 계정 지정은 위임일 뿐 사용자 허용 아님, 루트는 정책 관리 항상 가능), SQS 메시지 속성(MD5 검증). 선택적 SigV4 검증, SQS FIFO, DynamoDB 400KB 한도, 검사 시나리오 7개, 설정 파일·설정 화면, SKILL.md.
- 이후 추가: JSON 상태 스냅샷, 3D(Three.js) 캐릭터 마을(본섬 28개 시설 + 다리 건너 다운타운 + 모노레일 건너 "연대기 섬": 계획서 0~10단계 오벨리스크와 SigV4·FIFO·400KB·SDK 경기장·릴리스·Homebrew·Docker·우분투·검사관 훈련장·Pages 포털·/_ui 전광판, `town.html` 12절), GitHub Pages 마을(`pages.yml`). Pages 마을은 방문자 PC의 로컬 에뮬레이터
  (`127.0.0.1:4566`, `?api=`)에 SSE로 붙어 실제 트래픽을 보여 주고, 연결 전에는 목업 트래픽을 돌린다. Pages에서는 자동 연결·재시도를 하지 않고 🔌 연결 버튼을 눌렀을 때만 붙는다(실패한 연결마다 브라우저가 ERR_CONNECTION_REFUSED를 콘솔에 남기기 때문). `/_town`(같은 출처)은 자동 연결.
- `v0.1.0` 릴리스 완료(2026-11-21): 바이너리 3종 + SHA256SUMS, Homebrew sha256 반영.
- `v0.1.1` 릴리스 완료(2026-11-21): SIGTERM·Ctrl-C 뒤 최대 2초 안에 종료(v0.1.0은 열린 연결 때문에 안 끝날 수 있었음). Homebrew 포뮬러 0.1.1 반영.
  macOS 러너는 `macos-latest`를 쓴다(버전 고정 러너 macos-13·14는 폐지됨).
- Netlify 배포는 GitHub Pages로 대체됨(필요하면 사용자 계정 연결).
- 이름은 `rocalcloud`(r로 시작, 사용자가 정함), 라이선스 Apache-2.0. 이름에 AWS/Amazon 금지.

## 2. 구조

```
core/            Rust 단일 바이너리 (axum + tokio), 모든 서비스가 여기 있다
  src/main.rs    라우팅, 인증(서명 검증·IAM 판정), 장애 주입, 이벤트 발행, 관리 엔드포인트, 설정(RC_CONFIG)
  src/sigv4.rs   SigV4 서명·검증(VERIFY_SIGV4=1), HMAC은 sha2로 직접 구현
  src/<svc>.rs   서비스별 모듈. 상태 struct + handle() + admin()
  src/ui.html    관리 GUI (/_ui), town.html 캐릭터 마을 (/_town) — include_str!로 내장
gui/             Tauri 2 창. /_ui를 여는 껍데기일 뿐
tests/sdk_test.py  boto3 호환성 테스트 28개 (주 통합 테스트), tests/js·tests/rust는 JS v3·Rust SDK 스위트
netlify.toml     예전 Netlify 설정(지금은 GitHub Pages `pages.yml`로 배포)
```

서비스 모듈: ddb, s3, sqs, sns, iam(+STS, 정책 평가기), net(EC2 VPC + 도달성), secrets, ssm, kms, logs,
lambda, events, sfn, apigw, cognito, kinesis, ses, managed(RDS·ElastiCache, Docker), ecs, elb, route53(+DNS), cfn,
agent(해설 에이전트), inspector(검증 에이전트).

### 요청 흐름 (main.rs `handle`)
1. SigV4 헤더에서 access key와 서비스 이름을 읽는다. `VERIFY_SIGV4=1`이면 3단계 전에 서명을 검증한다.
2. `Svc` enum으로 분류: X-Amz-Target(JSON 프로토콜), 경로(REST), form `Action`+`Version`(Query 프로토콜).
3. `checks()`가 (IAM action, resource ARN) 목록을 만들고 `iam.authorize()`로 판정. `ENFORCE_IAM=1`일 때만 거부.
4. `chaos_fault()`가 장애 주입 규칙 적용.
5. 서비스 handle 호출 → 프로토콜별 응답(json_reply / query_reply / ec2_reply / XML).
6. 이벤트를 `emit()`으로 발행: SSE `/_events`, 최근 1000건은 `app.recent`(에이전트용).

### 새 서비스를 붙이는 방법 (반복된 패턴)
- `src/x.rs`에 `#[derive(Default)] pub struct X`, `pub fn handle(&mut self, op, &Value) -> Result<Value, ApiErr>`,
  `pub fn admin(&self) -> Value` (GUI 공통 표 형식: `{name, count, sub, cols, rows}`).
- main.rs: `mod x;`, `App`에 `Mutex<x::X>` 필드와 초기화, `reset()`에 초기화, `state()`에 admin,
  JSON 서비스면 `JSON_TARGETS`와 Json 분기, 아니면 `Svc` variant + 분류 + `checks` + 응답 match.
- ui.html의 `GENERIC` 배열에 `["x", "표시 이름"]`, town.html의 건물 `svc` 목록에 서비스 이름.
- tests/sdk_test.py에 `test_x()` 추가 (boto3로 정상·오류 경로 모두).
- 다른 서비스로 보내는 일(배달, 트리거)은 main.rs `send_to_target()`/`deliver()`를 쓴다.

### 관리 엔드포인트
`/_ui` `/_town` `/_events`(SSE) `/_admin/config` `/_admin/state` `/_admin/reset`(POST) `/_admin/reach` `/_admin/chaos`(GET/POST)
`/_api/{apiId}/...`(API GW 호출) `/_cognito/{pool}/.well-known/*` `/_agent/status|explain|ask|template` `/_inspect/run|reports|report/{id}|replay`.
**POST 관리 엔드포인트는 `x-rocalcloud` 헤더를 요구한다**(다른 웹사이트의 CSRF 차단). 새 POST도 같은 규칙.

## 3. 실행과 테스트

```sh
cd core && cargo build                       # 경고 0개 유지
ENFORCE_IAM=1 cargo run --release            # 127.0.0.1:4566
cargo test                                   # 단위 테스트
uv run --with boto3 --with "pyjwt[crypto]" --with pg8000 --with pymysql --with redis --with dnspython tests/sdk_test.py
```
- 테스트는 반드시 `ENFORCE_IAM=1` 서버로 돌린다. 서명 검증도 보려면 `ENFORCE_IAM=1 VERIFY_SIGV4=1`로 한 번 더(CI도 두 번 돈다). 맥에는 Docker 데몬이 없어 RDS·ECS 테스트는 `skip`으로 나온다.
- 전체 검증은 우분투에서 한다(아래 4절). 끝나면 남은 컨테이너가 0개인지 `docker ps -a`로 확인.
- 화면 확인은 Playwright + 설치된 Chrome: `uv run --with playwright python script.py` 안에서 `launch(channel="chrome")`.
  사용자의 Chrome 설정(Apple Events JS 등)은 바꾸지 않는다.

## 4. 우분투 원격 PC 및 맥 경량화 원칙 (사용자 장비, 한도 엄수)

- **맥 경량화 원칙 (필수)**: 맥에는 소스 코드만 가볍게 유지한다(~4 MB). `core/target`·`tests/rust/target`·`gui/target`·`tests/js/node_modules` 같은 무거운 빌드 산출물(수 GB)은 맥에 남기지 않고 우분투에서만 빌드·캐시한다. 맥에서 불가피하게 빌드했다면 작업 후 정리한다.
- `ssh ubuntu` (192.168.0.105). 코드는 맥에서 쓰고 `rsync -az --exclude target --exclude node_modules --exclude __pycache__ core tests tools gui README.md local-cloud-emulator-plan.md AGENTS.md CONTRIBUTING.md SKILL.md Dockerfile ubuntu:~/work/projects/rocalcloud/`.
- 원클릭 빌드·검증: `ssh ubuntu 'bash ~/work/projects/rocalcloud/tools/ubuntu_verify.sh'` (`nice -n 10`, `-j 8` 한도 준수, 단위 테스트·릴리스 빌드·`sdk_compare`·`partial_fail_check`·`mem_bench`·`db_query`·컨테이너 0개 확인까지 수행).
- 수동 빌드: `ssh ubuntu 'cd ~/work/projects/rocalcloud/core && nice -n 10 ~/.cargo/bin/cargo build --release -j 8'`.
- `Cargo.lock`이 우분투에서 갱신되면 `scp ubuntu:~/work/projects/rocalcloud/core/Cargo.lock core/Cargo.lock`으로 맥에 반영해 커밋한다.
- 사양 한도 문서: 우분투 `~/work/docs/SPEC.md`. **한도를 넘는 작업은 먼저 사용자에게 묻는다.**
  RAM 작업당 8 GiB, CPU 8스레드, 스왑 금지, GPU 80°C 금지, 전력 제한 180 W 변경 금지.
- 설치됨(사용자 승인): rustup(홈), docker.io(사용자는 docker 그룹), Ollama 0.40.16 + `qwen3.5:9b`.
- Ollama 설정: `/etc/systemd/system/ollama.service.d/rocalcloud.conf` (127.0.0.1, 모델 1개, 병렬 1, keep_alive 5m,
  LLAMA_ARG_CACHE_RAM=256, MemoryMax=8G, MemorySwapMax=0). 온도 감시 `ollama-gpu-guard.service`: 70°C 정지, 60°C 미만 재시작.
- GPU 실측: 최고 65°C, VRAM 6.5 GB(모델 약 6.3 GiB, 한도 6.5 GiB에 근접) → **더 큰 모델 금지**.
- 원격 명령 주의: `pkill -f "패턴"`은 ssh 셸 자신도 죽인다. `pkill -f "target/[r]elease/rocalcloud$"`처럼 쓴다.
  복잡한 인용은 스크립트 파일을 scp로 보내 실행한다. 출력 파싱에는 `LC_ALL=C`(로케일이 한국어).
- 맥 에뮬레이터에서 우분투 LLM을 쓰려면 `ssh -f -N -L 11434:127.0.0.1:11434 ubuntu`.

## 5. 작업 규칙 (사용자 선호)

- 응답과 문서는 한국어. 단계가 끝날 때마다 **커밋하고 푸시**한다(사용자가 반복 요청). 커밋 메시지 끝에 공동 저자 줄.
- 최소 구현 원칙: 표준 라이브러리 → 이미 있는 크레이트 → 짧은 코드. 새 크레이트는 이유가 있을 때만
  (지금까지: axum, tokio, serde_json, serde_yaml, base64, sha2, md-5, rsa, rand, zip, uuid, chrono, futures-util).
- 일부러 줄인 부분은 `// ponytail:` 주석으로 한계와 확장 방법을 남긴다(`grep -rn ponytail core/src`로 목록).
- 지원하지 않는 기능은 흉내 내지 말고 명확한 오류로 답한다(S3 501, `UnknownOperationException` 등).
- 보안 기본값: 모든 포트와 컨테이너는 127.0.0.1에만 연다. 실시간 이벤트 스트림에는 CORS를 열지 않는다
  (Cognito 확인 코드 등이 이벤트에 들어 있다). 예외는 GitHub Pages 마을 출처 하나(`RC_TOWN_ORIGIN`, 기본
  `https://jinyounghwa.github.io`, `off`로 끔, `Vary: Origin` 포함)이고, 그 사본은 `town_view()`가
  allowlist 필터링으로 시각화 필수 필드만 남겨 `code`·`principal`·`error`·`auth.reason`·`request_id` 등을 제거한다.
  `town.html`은 `?api=`를 루프백(`127.0.0.1`/`localhost`, IPv6 `[::1]`은 CSP가 막으므로 제외)으로만 제한하고 CSP와 `no-referrer`를 적용한다.
- LLM은 코어 바깥에만 둔다. LLM이 꺼져도 모든 기능이 동작해야 한다(규칙 기반 폴백 먼저).
- 결과 보고는 사실대로: 실패와 생략을 숨기지 않는다. 테스트 채점 기준이 느슨했다면 그것도 밝힌다.

## 6. 검증 에이전트 요점 (inspector.rs)
- 실행기·판정기는 결정적 코드, 대상은 127.0.0.1만. LLM은 시나리오 제안만 한다(꺼져 있으면 내장 시나리오만).
- 내장 시나리오 21개: 보안 8(버킷 정책 Deny·잠김 방지 포함), 장애 6(스로틀·5xx·지연·부분 실패·연결 끊김·부하 중 재생성), 사고 4(DLQ·Lambda 반복 실패·
  큐 폭주·저장소 한도), 성능 2(동시 처리량·메모리 증가), 퍼징 1. 파괴적 작업은 `rc-insp-` 접두사 리소스에서만.
- 요청은 `local_http()` 하나로 나가며 `resign()`이 진짜 SigV4로 서명한다(`sig_header()`의 `Signature=00`은 자리표시).
  `VERIFY_SIGV4=1`이면 서명 없는 요청도 루트로 서명한다. 서명 없이 보내야 하는 검사는 `x-rc-unsigned` 헤더를 단다.
- 새 시나리오: `sc_x()` 함수 → `run_inner()`의 `plan` 목록과 `match id`에 추가 → `make_result()`로 결과.

## 7. 다음에 할 일 (2026-11-21 기준, 우선순위 순)
계획서 4장 체크리스트는 전부 완료. 아래는 그 뒤에 남은 일이다.

1. ~~v0.1.1 릴리스~~ 완료(2026-11-21).
2. **우분투 전체 검증 1회.** 3D 개편과 종료 수정 뒤 `tools/ubuntu_verify.sh`를 끝까지 돌리지 않았다
   (CI와 같은 순서의 Python 스위트 두 모드만 통과 확인). 끝나면 `pgrep rocalcloud`·`docker ps -a`가 0인지 본다.
3. **CI 경고 정리.** Node 20 액션 폐지 경고: `actions/checkout@v5`, `actions/setup-node@v5`, `astral-sh/setup-uv` 최신으로.
   setup-uv 캐시 경고(`uv.lock` 없음)는 `enable-cache: false` 또는 `cache-dependency-glob` 지정.
4. **3D 마을 점검.** 저사양 GPU·모바일·Safari·Firefox 화면 확인(지금까지 맥 Chrome만 확인). 연대기 섬의 숫자
   (SDK 테스트 28/5/4개, 시나리오 21개, GPU 65°C)는 `town.html` 12절에 손으로 적은 값이라 테스트가 늘면 같이 고친다.
   맥에서 에뮬레이터를 띄운 `/_town` 실시간 모드는 이번 3D 개편 뒤 아직 직접 보지 않았다.
5. **알려진 한계(8절) 중 효과 큰 순서.** ~~SQS 메시지 속성~~(완료) → ~~S3 버킷 정책~~(완료, `iam.rs` `authorize_with`) → ~~SQS 큐 정책~~(완료) →
   Step Functions Parallel 진짜 병렬 → ALB 경로 규칙 → aws-chunked 조각 서명 검증. 각각 sdk_test.py에 정상·오류 경로 테스트를 같이 넣는다.
6. (선택) `?api=`로 IPv6 `[::1]`을 쓰려면 CSP `connect-src`가 IPv6 리터럴을 못 받으므로 별도 방법이 필요하다. 요청이 있을 때만.

큰 변경 뒤에는 4절 방법으로 우분투 전체 검증을 돌린다.

## 8. 알려진 한계 (요약)
상태는 기본 인메모리(JSON 스냅샷 `RC_STATE_FILE` 또는 SQLite `RC_SQLITE_FILE`로 영속 저장 가능), SigV4 서명은 `VERIFY_SIGV4=1`일 때만 검증(SigV2 거부,
aws-chunked 조각 서명은 미검증), SNS 토픽·Lambda 리소스 기반 정책 미평가(S3 버킷·SQS 큐 정책은 평가), KMS는 진짜 암호 아님,
ALB는 L4 라운드로빈(경로 규칙 없음), Step Functions 병렬 가지가 순차 실행, SNS→SQS 배달 시 메시지 속성 미전달, Query 프로토콜 구버전 SQS 미지원,
ECS 태스크가 에뮬레이터를 부르려면 `BIND=0.0.0.0:4566` 필요. 세부는 각 파일의 `ponytail:` 주석.
