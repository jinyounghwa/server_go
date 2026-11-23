# rocalcloud 3일 작업 인계서 (2026-11-24 ~ 2026-11-26)

이 문서는 잠시 일을 넘겨받는 작업자(모델)를 위한 3일치 계획이다. **먼저 `AGENTS.md` 전체를 읽는다.** 구조, 요청 흐름, 서비스 추가 패턴은 거기 있다.
이 문서와 AGENTS.md가 충돌하면 AGENTS.md가 맞다. 3일이 끝나면 AGENTS.md 7절을 갱신하고 이 문서는 지운다.

## 0. 꼭 지킬 것 (어기면 안 됨)

### 사용자 장비와 한도
- **맥 경량화.** 맥에서 `cargo build`, `npm install`을 하지 않는다. `core/target`, `node_modules` 같은 빌드 산출물은 우분투에만 둔다. 실수로 만들었으면 바로 지운다.
- **우분투 한도.** 작업당 RAM 8 GiB, CPU 8스레드(`-j 8`, `nice -n 10`), 스왑 금지, GPU 80°C 금지, 전력 제한 180 W는 바꾸지 않는다. **한도를 넘을 것 같으면 먼저 사용자에게 묻는다.** 더 큰 LLM 모델도 금지(VRAM 한계).
- **우분투 전원.** 시작할 때 `python3 tools/ubuntu_power.py wake --wait`로 켠다. 끝날 때는 남은 프로세스와 컨테이너가 0개인지 확인하고 `python3 tools/ubuntu_power.py off`로 끈다. 끄기에서 "Access denied" 문구가 나와도 `status`가 OFFLINE이면 꺼진 것이다.
- **원격 pkill.** `pkill -f "target/[r]elease/rocalcloud$"` 형태로만 쓴다. 그냥 패턴을 쓰면 ssh 셸 자신이 죽는다. 출력을 파싱할 때는 `LC_ALL=C`를 붙인다(우분투 로케일이 한국어).

### 보안 기본값 (절대 풀지 않음)
- 모든 포트와 컨테이너는 `127.0.0.1`에만 연다.
- `/_events`(SSE)에 CORS를 열지 않는다. 예외는 Pages 출처 하나뿐이고, 그 사본은 `town_view()` allowlist로 걸러진다.
- POST 관리 엔드포인트는 `x-rocalcloud` 헤더를 요구한다. 새 POST도 같다.
- 비밀은 커밋하지 않는다(`.ubuntu_power.env` 등). 사용자 이메일이나 개인정보를 외부 요청에 넣지 않는다.
- LLM은 코어 바깥에만 둔다. LLM이 꺼져도 모든 기능이 돌아야 한다.

### 작업 방식
- 응답과 문서는 **한국어**로 쓴다.
- 한 항목이 끝날 때마다 **커밋하고 푸시**한다. 커밋 메시지 끝에 공동 저자 줄을 넣는다.
- 푸시한 뒤에는 CI(`gh run list --limit 3`)가 초록인지 확인한다. 빨간색이면 다음 항목으로 넘어가지 않는다.
- **최소 구현.** 표준 라이브러리 → 이미 있는 크레이트 → 짧은 코드 순서로 고른다. 새 크레이트는 이유를 적을 수 있을 때만 추가한다.
- 일부러 줄인 부분에는 `// ponytail:` 주석으로 한계와 확장 방법을 남긴다. 지원하지 않는 기능은 흉내 내지 말고 명확한 오류로 답한다.
- 빌드 경고는 0개를 유지한다.
- **결과 보고는 사실대로 한다.** 테스트하지 않은 경로, 실패, 생략, 느슨한 채점 기준을 숨기지 않는다.
- **사용자 확인이 필요한 일.**
  - 릴리스 태그 푸시는 사용자에게 먼저 묻는다(외부 공개, 되돌리기 어려움).
  - 한도를 넘는 작업, 새 패키지 설치, 실기기 점검도 묻는다.

### 매 항목 공통 완료 조건
1. `cargo test` 단위 테스트를 추가하고 통과시킨다.
2. `tests/sdk_test.py`에 정상 경로와 오류 경로를 모두 넣는다.
3. 우분투에서 SDK 스위트를 `ENFORCE_IAM=1`과 `ENFORCE_IAM=1 VERIFY_SIGV4=1` 두 번 돌려 실패 0개를 확인한다.
4. `docker ps -a`로 남은 컨테이너가 0개인지 확인한다.
5. 필요하면 `town.html`, `ui.html`, README, AGENTS.md 8절(한계)을 갱신한다.
6. 커밋하고 푸시한 뒤 CI가 초록인지 확인한다.

### 작업 루프 (복사해서 쓰기)
```sh
python3 tools/ubuntu_power.py wake --wait
rsync -az --exclude target --exclude node_modules --exclude __pycache__ core tests tools gui README.md local-cloud-emulator-plan.md AGENTS.md CONTRIBUTING.md SKILL.md Dockerfile ubuntu:~/work/projects/rocalcloud/
ssh ubuntu 'cd ~/work/projects/rocalcloud/core && nice -n 10 ~/.cargo/bin/cargo test -j 8 && nice -n 10 ~/.cargo/bin/cargo build --release -j 8'
ssh ubuntu 'bash ~/work/projects/rocalcloud/tools/ubuntu_verify.sh'   # 큰 변경 뒤 전체 검증
# Cargo.lock이 바뀌었으면: scp ubuntu:~/work/projects/rocalcloud/core/Cargo.lock core/Cargo.lock
```

---

## 1일차 (2026-11-24): 기준선 확인 + IAM 조건 연산자 (AGENTS.md 7절 6번)

### 1-1. 기준선 (30분)
- 우분투를 켜고 rsync한 뒤 `ubuntu_verify.sh`를 돌린다. 지금 `main`(커밋 `7ff002f` 이후)이 깨끗하게 통과하는지 먼저 확인한다.
- 단위 테스트는 26개다. 여기서 실패가 나오면 새 작업보다 그 원인부터 고친다.

### 1-2. 조건 연산자
현재 상태는 다음과 같다.
- `core/src/iam.rs`의 `cond_ok()`(117행 근처)는 String\*, Arn\*, Bool과 `IfExists`만 지원한다. 나머지 연산자는 항상 불일치다.
- 컨텍스트는 `HashMap<String, String>`이라 키 하나에 값 하나만 담긴다.

추가할 것:
- **Numeric 연산자:** `NumericEquals`, `NumericNotEquals`, `NumericLessThan`, `NumericLessThanEquals`, `NumericGreaterThan`, `NumericGreaterThanEquals`. f64로 파싱하고, 파싱에 실패하면 불일치로 본다.
- **Date 연산자:** `DateEquals`, `DateNotEquals`, `DateLessThan`, `DateLessThanEquals`, `DateGreaterThan`, `DateGreaterThanEquals`.
  - 값은 ISO 8601이나 epoch 초다. 이미 있는 `chrono`를 쓴다.
  - 컨텍스트에 `aws:CurrentTime`(ISO)과 `aws:EpochTime`을 요청 시각으로 넣는다. 넣는 곳은 `iam.rs` 158행 근처, `aws:SecureTransport`를 넣는 자리다.
- **IP 연산자:** `IpAddress`, `NotIpAddress`.
  - CIDR 비교는 `std::net::IpAddr`로 직접 짠다(짧다). 새 크레이트는 쓰지 않는다.
  - 컨텍스트에 `aws:SourceIp`를 넣는다. 에뮬레이터는 127.0.0.1에서만 받으므로 실제 피어 주소를 쓴다. 피어 주소를 얻기 어려우면 `127.0.0.1`로 둔다.
- **Null:** `"Null": {"k": "true"}`는 키가 없을 때 참이다.
- **ForAnyValue: / ForAllValues: 접두사.**
  - 값이 여러 개인 키(예: `aws:TagKeys`)를 위해 컨텍스트 값을 쉼표나 배열로 담는다. 바꾸는 범위는 `cond_ok` 안에서 끝나게 최소로 한다.
  - ForAllValues는 키가 없으면 참이다(AWS 동작). ForAnyValue는 키가 없으면 거짓이다.
- 지원하지 않는 연산자는 지금처럼 불일치로 둔다. Deny 문의 조건이라면 불일치가 덜 막는 쪽이라는 점을 `ponytail:` 주석에 적는다.

테스트:
- `glob_and_conditions` 단위 테스트를 연산자마다 참과 거짓으로 늘린다.
- sdk_test.py 예시 두 가지를 넣는다.
  - `DateGreaterThan`의 기준을 미래로 잡은 Deny 문 → 허용되어야 한다.
  - `NotIpAddress 10.0.0.0/8` Deny 문 → 127.0.0.1에서 온 요청은 막혀야 한다.
- `ponytail:` 주석(116행)을 새 지원 범위로 고친다.

---

## 2일차 (2026-11-25): 엄격 배달 정책 스위치 (7번) + 테스트하지 않은 경로 메우기

### 2-1. 엄격 배달 정책 (선택 항목이지만 할 것)
- `iam.rs` `service_may()`는 지금 대상에 정책이 없으면 허용한다. AWS는 거부한다.
- 설정 스위치를 추가한다.
  - 환경 변수 `RC_STRICT_DELIVERY=1`과 `RC_CONFIG` 설정 파일 키를 같이 둔다. 기존 설정을 읽는 방식은 `main.rs`를 본다.
  - 이 스위치가 켜져 있을 때만 정책 없음을 거부로 바꾼다.
  - 기본값은 꺼짐이다. 기존 사용자 흐름이 깨지면 안 된다.
- 적용 범위는 `main.rs` `service_gate`(ENFORCE_IAM이 켜져 있고 from이 sns, events, s3일 때)다. 거부되면 지금처럼 403 이벤트를 남긴다.
- 설정 화면(`ui.html`)에 스위치 표시가 있으면 같이 넣는다.
- 테스트: 스위치를 켜고 서버를 하나 더 띄우기는 무거우니, `service_may`의 strict 인자 단위 테스트로 판정을 확인한다. SDK 스위트는 기본 모드에서 그대로 통과해야 한다.

### 2-2. 지난 세션에서 테스트하지 않은 경로 (정직하게 보고한 것들)
아래는 코드만 있고 검증하지 않은 경로다. sdk_test.py에 짧은 테스트를 하나씩 붙인다. 실패하면 고친다.
1. **Kinesis → Lambda 실패 재시도와 건너뛰기:** 항상 실패하는 함수에 `MaximumRetryAttempts=1`을 건다. 그다음 레코드가 결국 처리되는지(샤드가 풀리는지) 확인한다.
2. **EventBridge·SNS 대상에 Lambda 별칭 ARN(`...:function:f:live`):** 별칭이 가리키는 버전으로 실행되는지 확인한다. 함수가 기록한 `AWS_LAMBDA_FUNCTION_VERSION`으로 본다.
3. **SNS→SQS 이외의 배달 정책 판정:** 아래 두 경우에 Deny 정책이 실제로 막는지 확인한다.
   - S3 알림 → SQS
   - EventBridge → SQS
   - 이벤트의 `auth.source`는 "queue policy"여야 한다.
4. **cron 실제 발화:** 벽시계를 기다리지 말고 `events.rs`의 `cron_next` 단위 테스트를 경계값으로 늘린다.
   - 경계값: 월말, 윤년 2월 29일, 요일 `MON-FRI`, 연도 필드.
   - 실발화는 확인하지 않았다고 보고에 적는다.

---

## 3일차 (2026-11-26): v0.1.5 릴리스 준비 + 문서 정리

### 3-1. 릴리스 준비 (태그 푸시는 사용자 승인 후)
v0.1.5에 들어갈 것:
- EventBridge `cron()`과 InputTransformer
- Kinesis → Lambda
- DynamoDB `list[i]` 경로
- Lambda 버전·별칭
- 1~2일차 결과

절차 (v0.1.4 때와 같음):
1. 버전을 0.1.5로 올린다: `core/Cargo.toml`, 그리고 우분투 빌드 뒤 `Cargo.lock`을 scp로 가져온다. `town.html`의 "v0.1.4 발사대"와 연대기 섬 9단계 줄도 고친다.
2. 우분투에서 `ubuntu_verify.sh` 전체를 통과시키고 커밋·푸시한다. CI가 초록인지 확인한다.
3. **사용자에게 "v0.1.5 태그를 푸시할까요?"라고 묻는다.** 승인을 받은 뒤에만 `git tag v0.1.5 && git push origin v0.1.5`를 한다. 그러면 `release.yml`이 바이너리 3종과 `SHA256SUMS.txt`를 만든다.
4. `gh release download v0.1.5 -p SHA256SUMS.txt`로 체크섬을 받는다. 파일명이 `SHA256SUMS`가 아니라는 점에 주의한다.
5. `packaging/homebrew/rocalcloud.rb`에 버전과 sha256 세 개(arm, x86 mac, linux)를 반영하고 커밋·푸시한다.
6. 우분투에서 리눅스 바이너리를 받아 다음을 확인한다.
   - 체크섬이 맞는다.
   - `/_admin/state`가 200을 돌려준다.
   - 종료가 2초 안에 끝난다.
   - 맥 바이너리는 실행해 보지 않았다면 그렇다고 적는다.

### 3-2. 문서
- AGENTS.md를 갱신한다.
  - 1절: v0.1.5 줄을 넣는다.
  - 7절: 끝낸 항목에 취소선을 긋는다.
  - 8절: 한계를 새로 고친다. 조건 연산자와 엄격 모드를 반영한다.
- 날짜(2026-11-26)를 적는다.
- README의 기능 목록과 `local-cloud-emulator-plan.md`를 필요한 만큼만 고친다.
- `town.html` 12절의 손으로 적은 숫자를 실제 값과 맞춘다(SDK 테스트 개수, 시나리오 21개 등).
- `grep -rn ponytail core/src`(지금 39개)에서 이번에 해결한 항목의 주석을 지운다.
- 이 문서(`HANDOFF.md`)는 지우고, 남은 일은 AGENTS.md 7절로 옮긴다.

### 3-3. 시간이 남으면 (요청이 없으면 하지 않음)
- 8번 IPv6 `?api=[::1]`은 하지 않는다. CSP가 IPv6 리터럴을 못 받기 때문에, 사용자가 요청할 때만 한다.
- 실기기 점검(휴대폰, Safari, 약한 노트북)은 사용자가 있어야 한다. 사용자에게 제안만 한다.

---

## 끝낼 때 보고 형식 (매일)
- 한 일과 커밋 해시, CI 결과
- 테스트한 것과 **테스트하지 않은 것**을 구분해 적는다.
- 우분투 상태: 프로세스 0개, 컨테이너 0개, 전원 끔
- 다음 날 할 일과 막힌 점(사용자 결정이 필요한 것)
