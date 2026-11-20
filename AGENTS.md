# rocalcloud — 인수인계 지침 (2026-11-20)

다음 작업자(모델)가 바로 이어서 코딩할 수 있도록 현재 상태, 규칙, 남은 일을 정리한 문서다.
계획 원본은 `local-cloud-emulator-plan.md`. 이 문서와 충돌하면 계획서가 목표, 이 문서가 현재 사실이다.

## 1. 현재 상태

- 계획서 6장 순서 **1~8단계 전부 완료** (코어·22개 서비스·GUI·캐릭터 마을·해설 에이전트·검증 에이전트·Python/JS/Rust 3개 SDK 호환성 스위트·Dockerfile/Homebrew/GitHub Actions CI·Release 패키징·문서 정비).
- 이후 추가: JSON 상태 스냅샷, 3D(Three.js) 캐릭터 마을, GitHub Pages 마을(`pages.yml`). Pages 마을은 방문자 PC의 로컬 에뮬레이터
  (`127.0.0.1:4566`, `?api=`)에 SSE로 붙어 실제 트래픽을 보여 주고, 연결 전에만 목업 트래픽을 돌린다(5초마다 재시도).
- `v0.1.0` 릴리스 완료(2026-11-21): 바이너리 3종 + SHA256SUMS, Homebrew sha256 반영.
  macOS 러너는 `macos-latest`를 쓴다(버전 고정 러너 macos-13·14는 폐지됨).
- Netlify 배포는 GitHub Pages로 대체됨(필요하면 사용자 계정 연결).
- 이름은 `rocalcloud`(r로 시작, 사용자가 정함), 라이선스 Apache-2.0. 이름에 AWS/Amazon 금지.

## 2. 구조

```
core/            Rust 단일 바이너리 (axum + tokio), 모든 서비스가 여기 있다
  src/main.rs    라우팅, 인증(IAM 판정), 장애 주입, 이벤트 발행, 관리 엔드포인트
  src/<svc>.rs   서비스별 모듈. 상태 struct + handle() + admin()
  src/ui.html    관리 GUI (/_ui), town.html 캐릭터 마을 (/_town) — include_str!로 내장
gui/             Tauri 2 창. /_ui를 여는 껍데기일 뿐
tests/sdk_test.py  boto3 호환성 테스트 23개 (유일한 통합 테스트)
netlify.toml     마을 데모 정적 배포 설정 (배포는 아직 안 함)
```

서비스 모듈: ddb, s3, sqs, sns, iam(+STS, 정책 평가기), net(EC2 VPC + 도달성), secrets, ssm, kms, logs,
lambda, events, sfn, apigw, cognito, kinesis, ses, managed(RDS·ElastiCache, Docker), ecs, elb, route53(+DNS), cfn,
agent(해설 에이전트), inspector(검증 에이전트).

### 요청 흐름 (main.rs `handle`)
1. SigV4 헤더에서 access key와 서비스 이름을 읽는다(서명 검증은 안 함).
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
`/_ui` `/_town` `/_events`(SSE) `/_admin/state` `/_admin/reset`(POST) `/_admin/reach` `/_admin/chaos`(GET/POST)
`/_api/{apiId}/...`(API GW 호출) `/_cognito/{pool}/.well-known/*` `/_agent/status|explain|ask|template` `/_inspect/run|reports|report/{id}|replay`.
**POST 관리 엔드포인트는 `x-rocalcloud` 헤더를 요구한다**(다른 웹사이트의 CSRF 차단). 새 POST도 같은 규칙.

## 3. 실행과 테스트

```sh
cd core && cargo build                       # 경고 0개 유지
ENFORCE_IAM=1 cargo run --release            # 127.0.0.1:4566
cargo test                                   # 단위 테스트
uv run --with boto3 --with "pyjwt[crypto]" --with pg8000 --with pymysql --with redis --with dnspython tests/sdk_test.py
```
- 테스트는 반드시 `ENFORCE_IAM=1` 서버로 돌린다. 맥에는 Docker 데몬이 없어 RDS·ECS 테스트는 `skip`으로 나온다.
- 전체 검증은 우분투에서 한다(아래 4절). 끝나면 남은 컨테이너가 0개인지 `docker ps -a`로 확인.
- 화면 확인은 Playwright + 설치된 Chrome: `uv run --with playwright python script.py` 안에서 `launch(channel="chrome")`.
  사용자의 Chrome 설정(Apple Events JS 등)은 바꾸지 않는다.

## 4. 우분투 원격 PC (사용자 장비, 한도 엄수)

- `ssh ubuntu` (192.168.0.105). 코드는 맥에서 쓰고 `rsync -az --exclude target core tests ubuntu:~/work/projects/rocalcloud/`.
- 빌드: `ssh ubuntu 'cd ~/work/projects/rocalcloud/core && nice -n 10 ~/.cargo/bin/cargo build --release -j 8'`.
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
  (Cognito 확인 코드가 이벤트에 들어 있다). 예외는 GitHub Pages 마을 출처 하나(`RC_TOWN_ORIGIN`, 기본
  `https://jinyounghwa.github.io`, `off`로 끔)이고, 그 사본은 `town_view()`가 `code` 필드를 지운다.
- LLM은 코어 바깥에만 둔다. LLM이 꺼져도 모든 기능이 동작해야 한다(규칙 기반 폴백 먼저).
- 결과 보고는 사실대로: 실패와 생략을 숨기지 않는다. 테스트 채점 기준이 느슨했다면 그것도 밝힌다.

## 6. 다음 일: 7단계 검증 에이전트 (계획서 10절)

권장 설계 (기존 코드를 재사용):
- `core/src/inspector.rs` + `POST /_inspect/run`(헤더 필수), 진행은 이벤트(`service: "inspector"`)로 발행.
- **실행기는 결정적 코드**: 시나리오는 `{name, kind, steps:[{service, op, params}], expect:{status, error_code}}` JSON.
  에뮬레이터 자신에게만 요청한다(외부 네트워크 금지, 대상은 127.0.0.1만 허용).
  내부 호출은 agent.rs `call_api()`나 cfn.rs의 내부 호출 방식을 재사용.
- **판정기는 규칙**: 기대 status/오류 코드와 실제 비교. LLM 판정 금지.
- **LLM은 시나리오 생성기로만**: agent.rs `chat()`(직렬화·간격·짧은 출력 이미 구현)과 JSON 스키마 강제.
  LLM이 꺼져 있으면 내장 기본 시나리오만 돈다.
- 기본 시나리오(우선순위): IAM 거부(명시·암묵), S3 키 경로 조작(`../`, 인코딩), 과대 페이로드(256 MiB 한도),
  서명 누락 요청, chaos(스로틀·5xx) 중 SDK 재시도, DLQ 적체, Lambda 반복 실패, 동시 요청 처리량,
  무작위 입력 퍼징(패닉 탐지: 서버가 계속 살아 있는지).
- 안전장치: 실행 횟수·시간 상한, 로컬 대상만, 파괴적 시나리오는 전용 접두사 리소스에서만.
- 리포트: 심각도별 목록 + 재현 요청 저장(`tests/regressions/*.json`), HTML/Markdown 내보내기.
- 화면: ui.html에 검사 탭(진행률, 통과/실패, 재현 요청), town.html에 검사관 캐릭터(경비가 막으면 성공 연출).
- `test_inspector`를 sdk_test.py에 추가.

## 7. 그다음: 8단계 (계획서 9절)
- JS(@aws-sdk v3)와 Rust(aws-sdk-rust) 호환성 스위트 추가(지금은 Python만).
- 패키징: 릴리스 바이너리, brew, Dockerfile. README의 지원 API 표 점검. 상표·이름 최종 확인.
- Netlify 데모 배포는 사용자 계정 연결이 필요하다(직접 하지 말고 물어볼 것).

## 8. 알려진 한계 (요약)
상태는 메모리 전용(SQLite·스냅샷 없음), SigV4 서명 미검증, 리소스 기반 정책 미평가, KMS는 진짜 암호 아님,
ALB는 L4 라운드로빈(경로 규칙 없음), Step Functions 병렬 가지가 순차 실행, Query 프로토콜 구버전 SQS 미지원,
ECS 태스크가 에뮬레이터를 부르려면 `BIND=0.0.0.0:4566` 필요. 세부는 각 파일의 `ponytail:` 주석.
