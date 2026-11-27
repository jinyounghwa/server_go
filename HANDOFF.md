# rocalcloud 작업 계획서 (2026-11-25 ~ 2027-02-07, 75일 — 75일차가 끝)

이 문서는 일을 넘겨받는 작업자(모델)를 위한 날짜별 계획서다. **먼저 `AGENTS.md` 전체를 읽는다.** 구조, 요청 흐름, 서비스 추가 패턴은 거기 있다.
이 문서와 AGENTS.md가 충돌하면 AGENTS.md가 맞다.

**이 문서는 지우지 않는다. 계속 이어 쓰는 계획서다.**
- 하루가 끝나면 그날 제목 옆에 `✅ 완료`, `⚠️ 일부`, `❌ 못 함` 중 하나와 커밋 해시를 적는다.
- 못 끝낸 일은 다음 날 맨 앞으로 옮긴다. 다른 날 항목을 건너뛰어 먼저 하지 않는다.
- **75일차가 마지막이다.** 그 뒤에는 새 계획을 쓰지 않고 유지보수 모드로 간다(75일차 참고). 새 서비스(Athena, Glue 등) 추가는 이 계획 범위 밖이며 사용자가 따로 요청할 때만 한다.
- 범위: 지금 에뮬레이트하는 서비스의 `ponytail:` 한계를 75일차까지 모두 구현하거나 명확한 거부로 정리한다. 75일차에 `grep -rn ponytail core/src` 결과는 "의도적 거부" 주석만 남아야 한다.
- **하루 분량은 넉넉히 잡았다.** 일찍 끝나도 다음 날 항목을 당겨 시작하지 말고 그날 항목의 점검·테스트·문서를 마무리한다. 그래도 시간이 남으면 그날 제목 옆 결과에 "다음 날 착수"라고 적고 다음 날 항목을 시작한다.
- **새 크레이트가 필요한 항목**(TLS의 rustls, 진짜 암호의 aes-gcm, SigV4a의 p256 등)은 시작 전에 사용자에게 묻는다. 답이 없으면 대안 범위만 하고 건너뛴다.

**지난 1차(11-24~26) 결과:** 커밋 9개(`5982113`~`4e4191f`)가 들어갔고 CI는 전부 초록이다.
- 계획했던 일: IAM 조건 연산자, `STRICT_DELIVERY=1`, 테스트하지 않은 경로 테스트(`test_handoff_edge_paths`).
- 계획보다 더 한 일:
  - SNS 필터 numeric·suffix
  - SigV4 시계 오차
  - STS 만료
  - Kinesis 리샤딩
  - S3 알림 대상 검증
  - Route53 라우팅 정책
  - Logs 필터 패턴
- boto3 테스트는 33개다.
- **아직 안 된 것:**
  - v0.1.5 릴리스: 태그가 아직 `v0.1.4`이고, `Cargo.toml`도 0.1.4다.
  - 문서 정리: AGENTS.md 2절은 아직 "테스트 28개", 머리말 날짜는 11-22다.
  - 우분투 전체 검증: 했다는 기록이 없다.

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

## 1일차 (2026-11-25): 지난 작업 검증 + v0.1.5 릴리스 — ⚠️ 일부 (`7d11e7e`): 우분투 전체 검증 통과(스위트 두 모드 실패 0), 버전 0.1.5·문서 갱신·CI 초록. 태그 푸시·Homebrew는 사용자 승인 대기

### 1-1. 우분투 전체 검증 (가장 먼저)
- 11-23 커밋 9개는 CI만 통과했고, 우분투에서 Docker를 포함한 전체 검증을 했는지 기록이 없다.
- 우분투를 켜고 rsync한 뒤 `ubuntu_verify.sh`를 돌린다. SDK 스위트도 두 모드(`ENFORCE_IAM=1`, `+VERIFY_SIGV4=1`)로 돌린다.
- `STRICT_DELIVERY=1` 테스트는 4567 포트로 두 번째 서버를 띄운다. 끝나면 그 프로세스도 남지 않았는지 본다.
- 실패가 있으면 릴리스하지 말고 먼저 고친다.

### 1-2. v0.1.5 릴리스 (태그 푸시는 사용자 승인 후)
포함할 것은 11-22 작업(cron·InputTransformer, Kinesis→Lambda, DynamoDB `list[i]`, Lambda 버전·별칭)과 11-23 커밋 9개 전부다.

1. 버전을 0.1.5로 올린다.
   - `core/Cargo.toml`을 고치고, 우분투 빌드 뒤 `Cargo.lock`을 scp로 가져온다.
   - `town.html`의 "v0.1.4 발사대"와 연대기 섬 9단계 줄도 고친다.
2. 문서를 맞춘다(같은 커밋).
   - AGENTS.md 머리말 날짜를 고친다.
   - AGENTS.md 1절에 v0.1.5 줄을 넣는다.
   - AGENTS.md 2절의 "테스트 28개"를 실제 개수로 고친다. `grep -c "^def test_" tests/sdk_test.py`가 지금 33이다.
   - `town.html` 12절의 SDK 숫자와 AGENTS.md 7절 1번의 "32/5/4"를 실제 값과 맞춘다. JS·Rust 스위트 개수도 센다.
   - README 기능 목록을 고친다.
3. 커밋·푸시하고 CI가 초록인지 확인한다.
4. **사용자에게 "v0.1.5 태그를 푸시할까요?"라고 묻는다.** 승인을 받은 뒤에만 `git tag v0.1.5 && git push origin v0.1.5`를 한다.
5. `gh run watch`로 Release 워크플로가 성공하는지 본다. 그다음 `gh release download v0.1.5 -p SHA256SUMS.txt`로 체크섬을 받는다. 파일명은 `SHA256SUMS.txt`다.
6. `packaging/homebrew/rocalcloud.rb`에 버전과 sha256 세 개(arm, x86 mac, linux)를 반영하고 커밋·푸시한다.
7. 우분투에서 리눅스 바이너리를 받아 확인한다.
   - 체크섬이 맞는다.
   - `/_admin/state`가 200을 돌려준다.
   - 종료가 2초 안에 끝난다.
   - 맥 바이너리는 실행하지 않았으면 그렇다고 적는다.

---

## 2일차 (2026-11-26): Lambda 실패 처리 (ponytail 목록에서 실사용 빈도가 높은 것) — ✅ 완료 (`7b3056f`): 2-1·2-2 전부, 스위트 두 모드 통과

`lambda.rs` 3행과 605행의 `ponytail:` 주석을 기준으로 한다.

### 2-1. 비동기 호출 대상 (Destinations)
- 연산은 `PutFunctionEventInvokeConfig`, `GetFunctionEventInvokeConfig`, `UpdateFunctionEventInvokeConfig`, `DeleteFunctionEventInvokeConfig`다. 설정 항목은 `MaximumRetryAttempts`(0~2), `MaximumEventAgeInSeconds`, `DestinationConfig.OnSuccess/OnFailure`다.
- 동작:
  - `InvocationType=Event` 호출에 적용한다.
  - 함수가 실패하면 재시도 횟수만큼 다시 실행한다.
  - 끝내 실패하면 OnFailure로, 성공하면 OnSuccess로 보낸다. 대상은 SQS, SNS, Lambda, EventBridge 버스다.
  - 보내는 일은 기존 `main.rs` `send_to_target()`을 쓴다. 새 배달 경로를 만들지 않는다.
- 보내는 본문은 AWS 형식 `{version, timestamp, requestContext{requestId, functionArn, condition, approximateInvokeCount}, requestPayload, responseContext, responsePayload}`이다.
- 대상 ARN이 존재하지 않으면 저장할 때 거부한다. S3 알림 검증(`0ea0373`)과 같은 방식이다.
- 이 배달이 `service_gate`(대상 정책 판정)를 거치는지 결정하고 주석에 적는다. AWS에서는 함수 실행 역할 권한으로 보낸다. 최소 구현으로는 판정하지 않는 쪽이 맞다.
- 테스트:
  - 항상 실패하는 함수에 OnFailure로 SQS를 건다. 비동기 호출 한 번 뒤 큐에 `condition: RetriesExhausted` 메시지가 1개 들어오는지 본다.
  - 성공하는 함수에 OnSuccess로 SQS를 건다.
  - 없는 ARN을 넣으면 오류가 나는지 본다.

### 2-2. 이벤트 소스 매핑 실패 처리
- 대상은 Kinesis 매핑(`poll_kinesis`)이다.
  - `BisectBatchOnFunctionError`: 실패한 배치를 반으로 나눠 다시 시도한다.
  - `DestinationConfig.OnFailure`: 건너뛴 배치의 메타데이터를 SQS나 SNS로 보낸다.
- SQS 매핑은 AWS도 DLQ(큐의 redrive)를 쓰므로 손대지 않는다.
- 테스트: 레코드 4개 중 1개만 실패하는 함수로 나눠 시도가 일어나는지, 결국 실패 레코드 메타데이터만 OnFailure 큐로 가는지 본다.
- 끝나면 `lambda.rs` `ponytail:` 주석에서 해결한 항목을 지운다. `ui.html` Lambda 화면에 대상 표시를 넣고, 마을에 배달 화살표가 이미 있으면 그대로 쓴다.

---

## 3일차 (2026-11-27): DynamoDB 정확도 + 정리 — ✅ 완료: 3-1·3-2 구현·테스트·문서·전체 검증 통과. 3-3의 AGENTS.md 7절 갱신·우분투 전원 끄기는 13일차 마무리로 이연(연속 계획서)

### 3-1. DynamoDB 숫자 키 정밀도 (`ddb.rs` 8행)
- 지금 N 키를 f64로 정렬해서 15자리를 넘으면 정밀도가 깨진다. 예를 들어 `12345678901234567`과 `12345678901234568`이 같은 값으로 본다.
- 새 크레이트 없이 십진 문자열 비교로 바꾼다.
  - 부호 → 정수부 길이 → 자릿수 순서로 비교한다. 지수 표기는 정규화하고, 앞뒤 0을 정리한다.
  - DynamoDB 한계(38자리)를 넘으면 `ValidationException`으로 거부한다.
- 정렬 키와 `KeyConditionExpression`의 `<`, `BETWEEN`이 모두 이 비교를 쓰게 한다.
- 스냅샷과 SQLite 저장 형식이 바뀌면 옛 파일을 읽을 수 있는지도 확인한다.
- 단위 테스트에 큰 수, 음수, 소수, `1e3`과 `1000`이 같은 값인지를 넣는다. sdk_test.py에는 17자리 정렬 키 Query 하나를 넣는다.

### 3-2. 프로젝션 같은 원소 병합 (`ddb.rs` 649행)
- `ProjectionExpression="a[0].x, a[0].y"`는 지금 원소 두 개가 된다. AWS는 하나로 합친다.
- `graft`에서 같은 인덱스를 합친다. 단위 테스트를 하나 넣는다.

### 3-3. 마무리 (반드시)
- 우분투 전체 검증을 다시 돌린다.
- AGENTS.md를 갱신한다.
  - 1절: 11-25~27 추가분을 적는다.
  - 7절: 새 할 일 목록을 만든다. 남은 `ponytail:` 주석 중에서 고른다.
  - 8절: 한계를 고친다.
- `town.html` 12절의 숫자를 고친다.
- 이 문서의 3일차 제목 옆에 결과 표시를 단다(문서는 지우지 않는다).
- 커밋·푸시하고 CI가 초록인지 확인한다. 우분투를 끈다.

### 시간이 남으면 (요청이 없으면 하지 않음)
- IPv6 `?api=[::1]`는 하지 않는다. 사용자가 요청할 때만 한다.
- 실기기 점검(휴대폰, Safari, 약한 노트북)은 사용자에게 제안만 한다.
- API Gateway REST v1, Cognito SRP, CFN 중첩 스택처럼 큰 기능은 시작하지 말고 AGENTS.md 7절 후보로만 적는다.

---

## 4일차 (2026-11-28): SQS·SNS FIFO 보강 — ✅ 완료 (`2808d1c`): SQS 메시지별 DelaySeconds·SNS FIFO 토픽, 리팩토링·단위/boto3 테스트(37/35)·우분투 두 모드 통과
- **SQS 메시지별 `DelaySeconds`:** `sqs.rs` 13행 ponytail 주석의 항목이다.
  - 표준 큐는 SendMessage와 SendMessageBatch 항목마다 0~900초를 받는다.
  - FIFO 큐는 메시지별 지연을 `InvalidParameterValue`로 거부한다(AWS 동작). 큐 단위 지연만 쓴다.
- **SNS FIFO 토픽:**
  - `.fifo` 이름이면 `FifoTopic=true`가 있어야 만들 수 있다.
  - Publish에는 `MessageGroupId`가 필수이고, `MessageDeduplicationId` 또는 `ContentBasedDeduplication`으로 5분 안 중복을 버린다.
  - FIFO SQS 구독으로만 배달한다. 순서와 그룹 ID를 넘긴다.
  - `sns.rs` 2행의 "no FIFO dedup" 주석을 고친다.
- 테스트:
  - 지연 메시지는 지연 시간이 지나기 전에는 받을 수 없어야 한다. 1초 지연으로 확인한다.
  - 같은 중복 ID로 두 번 Publish하면 큐에는 1개만 들어와야 한다.
  - 표준 큐를 FIFO 토픽에 구독시키면 거부되어야 한다.

## 5일차 (2026-11-29): Step Functions JSONPath·내장 함수 — ✅ 완료 (`744c862`): JSONPath 확장(`[*]`·`[-1]`·`['key']`·`$$` 전파·`?()` 거부), 내장 함수 12종, 단위/boto3 테스트(39/36)·우분투 두 모드 통과
- **`sfn.rs` 3행:** JSONPath를 `$.a.b[0]` 이상으로 넓힌다.
  - `[*]`, `[-1]`, `['key']`, `$$.Execution.Id`, `$$.State.Name`, `$$.Map.Item.Value`(Context 객체)를 지원한다.
  - 필터식 `?()`는 거부하고 오류를 명확히 낸다.
- **`sfn.rs` 122행 내장 함수 추가:**
  - Array 계열: `ArrayPartition`, `ArrayContains`, `ArrayRange`, `ArrayGetItem`, `ArrayLength`, `ArrayUnique`
  - 인코딩·해시: `Base64Encode`, `Base64Decode`, `Hash`(SHA-256 등, sha2와 md-5가 이미 있다)
  - 문자열·JSON: `StringSplit`, `JsonMerge`
  - 숫자: `MathRandom`
  - 각각 표준 라이브러리 수준의 짧은 코드로 쓴다.
- 테스트: 내장 함수마다 단위 테스트를 하나씩 둔다. sdk_test.py에는 Pass 상태 `Parameters`로 여러 함수를 한 번에 쓰는 실행 하나를 넣는다.

## 6일차 (2026-11-30): EventBridge 재시도·DLQ·아카이브 — ✅ 완료 (`f9006b5`): 대상별 RetryPolicy·SQS DLQ(속성 포함)·아카이브/재생(스냅샷·replay-name)·API destinations 거부, 단위/boto3 테스트(40/37)·우분투 두 모드 통과
- **대상별 재시도와 DLQ:**
  - 대상의 `RetryPolicy`(`MaximumRetryAttempts`, `MaximumEventAgeInSeconds`)와 `DeadLetterConfig.Arn`(SQS)을 지원한다.
  - 배달이 실패하면 재시도한다. 끝내 실패하면 DLQ로 보내고 `ERROR_CODE` 같은 메시지 속성을 붙인다.
  - 대상 정책 거부나 없는 대상도 실패로 본다.
- **아카이브와 재생:**
  - `CreateArchive`(EventPattern 필터, 보관 기간), `DescribeArchive`, `ListArchives`, `DeleteArchive`
  - `StartReplay`(시간 범위, 대상 규칙 ARN 목록), `DescribeReplay`
  - 재생 이벤트에는 `replay-name` 필드를 붙인다.
  - 보관은 메모리에 하고 스냅샷에도 저장한다.
- API destinations는 계속 거부한다. 외부 HTTP를 호출하는 기능이라 보안 기본값과 맞지 않는다.
- 테스트:
  - 없는 Lambda 대상 + DLQ 조합에서 DLQ에 메시지 1개가 들어와야 한다.
  - 아카이브한 이벤트를 재생하면 대상 큐에 다시 들어와야 한다.

## 7일차 (2026-12-01): API Gateway 인가자 (JWT·Lambda) — ✅ 완료 (`c2799e2`): `Create/Get/Update/DeleteAuthorizer`·`UpdateRoute`, 로컬 Cognito RS256 JWT 검증(외부 issuer 거부)·Lambda REQUEST simple response 2.0(`requestContext.authorizer.lambda`), 401/403 분리, 단위/boto3 테스트(42/38)·우분투 두 모드 통과
- **`apigw.rs` 3행:** HTTP API 인가자를 넣는다. 연산은 `CreateAuthorizer`, `GetAuthorizer(s)`, `UpdateAuthorizer`, `DeleteAuthorizer`이고, 라우트의 `AuthorizationType`과 `AuthorizerId`를 연결한다.
- **JWT 인가자:**
  - issuer와 audience를 확인한다.
  - 로컬 Cognito 풀의 JWKS(`/_cognito/{pool}/.well-known/jwks.json`)로 RS256 서명을 검증한다. 이미 있는 `rsa`·`sha2` 크레이트를 쓴다.
  - 외부 issuer URL은 가져오지 않는다. 로컬 풀만 받고, 나머지는 명확한 오류로 답한다.
- **Lambda 인가자:**
  - payload format 2.0의 simple response `{isAuthorized, context}`를 지원한다.
  - context를 통합 이벤트의 `requestContext.authorizer.lambda`로 넘긴다.
- 거부는 401(토큰 없음)과 403(검증 실패)으로 나눈다.
- 테스트:
  - Cognito 로그인 토큰이 있으면 200, 토큰이 없으면 401, 변조된 토큰이면 401 또는 403
  - Lambda 인가자가 false를 돌려주면 403

## 8일차 (2026-12-02): API Gateway CORS·HTTP_PROXY·스테이지 변수 — ✅ 완료 (`1e5ae19`): CORS(사전 요청 204·실제 응답 헤더, `*`+Credentials 거부)·HTTP_PROXY(루프백만, 스테이지 변수 치환)·스테이지 변수 CRUD, 단위/boto3 테스트(44/39)·우분투 두 모드 통과
- **CORS 설정:** `CorsConfiguration`(AllowOrigins, Methods, Headers, MaxAge, Credentials)을 지원한다.
  - `/_api/...`에 대한 OPTIONS 사전 요청에 응답하고, 실제 응답에도 헤더를 단다.
  - **이것은 사용자 API의 CORS다.** `/_events` 관리 스트림의 CORS 규칙은 절대 건드리지 않는다.
- **HTTP_PROXY 통합:**
  - **대상 URL은 루프백(127.0.0.1, localhost)만 허용한다.** 그 밖은 저장할 때 거부한다. SSRF를 막기 위해서다.
  - 메서드, 경로, 쿼리, 헤더를 전달한다.
- **스테이지 변수:** `${stageVariables.x}`를 통합 URI에서 치환한다.
- `apigw.rs` 180행의 "deployments are no-ops" 주석은 그대로 둔다. 필요성이 낮다.
- 테스트:
  - 허용된 출처의 사전 요청이면 헤더가 붙고, 다른 출처면 헤더가 없어야 한다.
  - 루프백의 작은 HTTP 서버로 프록시가 되어야 한다. 테스트 안에서 파이썬 `http.server`를 띄운다.
  - 외부 URL 통합은 생성할 때 거부되어야 한다.

## 9일차 (2026-12-03): Cognito 그룹·Lambda 트리거 — ✅ 완료 (`c3a0642`): 그룹 CRUD·`cognito:groups` 클레임, PreSignUp(실패 시 가입 거부·autoConfirm)·PostConfirmation·PreTokenGeneration(클레임 추가/삭제), 단위/boto3 테스트(45/40)·우분투 두 모드 통과
- **`cognito.rs` 3행:** 그룹을 지원한다.
  - 연산: `CreateGroup`, `GetGroup`, `ListGroups`, `DeleteGroup`, `AdminAddUserToGroup`, `AdminRemoveUserFromGroup`, `AdminListGroupsForUser`
  - 토큰에 `cognito:groups` 클레임을 넣는다.
- **Lambda 트리거:** `LambdaConfig`의 `PreSignUp`, `PostConfirmation`, `PreTokenGeneration`
  - 이벤트 형식은 AWS와 같게 `{version, triggerSource, userPoolId, userName, request, response}`이다.
  - PreSignUp에서 `autoConfirmUser`를 반영한다. 함수가 실패하면 `UserLambdaValidationException`으로 답한다.
  - PreTokenGeneration에서 클레임 추가와 삭제를 반영한다.
- 7일차 JWT 인가자와 연결해 그룹 클레임이 `requestContext`에 보이는지 확인한다.
- 테스트: 그룹에 넣은 사용자 토큰에 클레임이 있어야 하고, PreSignUp이 거부하면 가입이 실패해야 한다.

## 10일차 (2026-12-04): Kinesis 보존·샤드 수 변경 + S3 목록 정확도 — ✅ 완료 (`6e4e622`): RetentionPeriodHours(만료 숨김·주입 시계 단위 테스트)·UpdateShardCount(1→2→1 무손실), S3 1000키 MaxKeys=7 delimiter 경계(코드 수정 불필요·테스트 추가), 단위/boto3 테스트(47/42)·우분투 두 모드 통과
- **`kinesis.rs` 3행:**
  - `RetentionPeriodHours`: 기본 24시간이다. `IncreaseStreamRetentionPeriod`와 `Decrease...`를 지원하고, 읽을 때 만료된 레코드를 숨긴다.
  - `UpdateShardCount`(UNIFORM_SCALING): 기존 Split·Merge 로직을 다시 쓴다.
- **`s3.rs` 326행 ListObjectsV2:** delimiter와 이어받기 토큰의 경계 경우를 점검한다.
  - 공통 접두사가 `MaxKeys` 경계에 걸릴 때 키가 빠지거나 중복되지 않아야 한다.
  - 접두사 끝 문자가 최대 코드포인트일 때도 확인한다.
  - 수정이 필요 없으면 테스트만 남긴다.
- 테스트:
  - 보존 기간이 지난 레코드는 GetRecords에 나오지 않아야 한다. 시계를 주입할 수 있는 단위 테스트로 확인한다.
  - 샤드 수를 1→2→1로 바꿔도 레코드가 유실되지 않아야 한다.
  - 키 1,000개를 `MaxKeys=7`과 delimiter로 끝까지 페이지 넘겼을 때 전체 집합이 정확해야 한다.

## 11일차 (2026-12-05): CloudFormation 제자리 업데이트·Export/ImportValue — ✅ 완료 (`3076f73`): 타입별 in-place 속성 업데이트(물리 ID 유지), Export/ImportValue·ListExports/ListImports·import 중 삭제/변경 거부, 단위/boto3 테스트(48/43)·우분투 두 모드 통과
- **`cfn.rs` 621행:** 교체가 필요 없는 속성 변경은 그 자리에서 고친다. 대상은 SQS 속성, Lambda 환경 변수·메모리·타임아웃, SNS 표시 이름, DynamoDB 처리량·TTL 정도다. 나머지는 지금처럼 교체한다.
  - 교체 여부 표는 리소스 타입별 짧은 목록으로 둔다.
- **`cfn.rs` 4행:**
  - `Outputs.Export.Name`과 `Fn::ImportValue`, `ListExports`, `ListImports`를 지원한다.
  - 다른 스택이 import한 export는 삭제나 변경을 거부한다(AWS 동작).
- **`cfn.rs` 665행:** 롤백할 때 교체된 리소스를 원래대로 되돌리지 못하는 한계를 이번 범위에서 줄일 수 있으면 줄인다. 안 되면 주석을 그대로 둔다.
- 테스트:
  - 큐의 `VisibilityTimeout`만 바꾼 업데이트에서 큐 URL(정체성)이 그대로여야 한다.
  - import하는 스택이 있으면 export하는 스택 삭제가 실패해야 한다.

## 12일차 (2026-12-06): 검증 에이전트·SDK 스위트·마을 따라잡기 — ✅ 완료 (`ef084a9`): 검사관 시나리오 27개(보안 4종·사고 2종 추가 및 `poll_sqs_body`/`xml_tag` 리팩토링), JS v3(8개)·Rust SDK(7개) 스위트 확장, `town.html`/`AGENTS.md` 동기화, 우분투 전체 검증(단위 48·boto3 43 두 모드·JS 8·Rust 7) 통과 (Playwright 화면 점검은 미실행)
- **`inspector.rs`에 새 시나리오** (현재 21개). 결정적으로 쓰고 `rc-insp-` 리소스만 쓴다.
  - 보안: 시계 오차 요청 거부, 만료된 STS 키 거부, `STRICT_DELIVERY`일 때 정책 없는 대상 배달 거부, JWT 인가자 우회 시도
  - 사고: Lambda Destinations OnFailure 도착, EventBridge DLQ 도착
  - AGENTS.md 6절의 시나리오 숫자를 고친다.
- **JS v3·Rust SDK 스위트**(`tests/js`, `tests/rust`)에 이번 기간 기능을 대표하는 테스트를 각각 3~5개 넣는다. Lambda 별칭, FIFO 토픽, Step Functions 내장 함수, 인가자가 후보다.
  - 이 스위트는 우분투에서만 빌드한다(맥 경량화).
- **마을과 GUI:**
  - 새 기능의 표시를 넣는다: `ui.html` 표, `town.html` 건물·배달 화살표.
  - 연대기 섬 숫자를 고친다(SDK 테스트 수, 시나리오 수).
  - 우분투 Playwright로 Pages 마을과 `/_town` 화면을 확인한다.

## 13일차 (2026-12-07): v0.1.6 릴리스 + 다음 10일 계획 — ✅ 완료·태그 대기 (`1bd323d`) (준비 내용:  우분투 전체 검증 통과, Playwright 화면 점검(Pages 마을·`/_town`·`/_ui` 콘솔 에러 0·자동 연결 확인; 스크린샷 판독은 이미지 미지원 세션이라 DOM/콘솔 기준), Cargo 0.1.6·`town.html`·AGENTS 갱신. **태그 푸시·Homebrew는 사용자 승인 대기**
- 우분투 전체 검증을 돌린다(두 모드와 `ubuntu_verify.sh`). 실패가 있으면 릴리스하지 않는다.
- v0.1.6을 준비한다. 절차는 1일차 1-2와 같다. 버전, `Cargo.lock`, `town.html`, 문서를 고친다.
  - **태그 푸시는 사용자 승인을 받은 뒤에만 한다.**
  - Homebrew sha256을 반영하고, 리눅스 바이너리로 확인한다.
- AGENTS.md를 갱신한다.
  - 1절: v0.1.6과 이번 기간 추가분을 적는다.
  - 7절: 할 일 목록을 고친다.
  - 8절: 한계를 고친다.
  - `grep -rn ponytail core/src`에서 해결한 주석이 지워졌는지 본다.
- 14~23일차 계획은 이미 아래에 있다(2026-11-26 추가). 1~12일차 결과를 보고 순서나 범위를 고칠 곳이 있으면 고치고, 고친 이유를 그 날 항목에 한 줄로 적는다.
- 12일차에 하지 않은 Playwright 화면 점검(Pages 마을·`/_town`·`/_ui`)을 여기서 한다.

---

## 14일차 (2026-12-08): Step Functions 작업 토큰·타임아웃 — ✅ 완료 (`d932454`): `.waitForTaskToken`·SendTaskSuccess/Failure/Heartbeat·TaskDoesNotExist/TaskTimedOut, TimeoutSeconds(기본 60초)·HeartbeatSeconds → States.Timeout→Retry/Catch, 단위/boto3 테스트(49/44)·우분투 두 모드 통과
- **`sfn.rs` 4행:** `.waitForTaskToken` 통합을 넣는다.
  - `$.Task.Token`을 Parameters로 넘기고, 실행은 토큰이 돌아올 때까지 멈춘다. 대상은 SQS `sendMessage`, SNS `publish`, Lambda `invoke`다.
  - 토큰을 돌려주는 연산은 `SendTaskSuccess`, `SendTaskFailure`, `SendTaskHeartbeat`다.
  - 모르는 토큰이나 이미 끝난 토큰에는 `TaskDoesNotExist` 또는 `TaskTimedOut`으로 답한다.
- **Task 상태의 `TimeoutSeconds`와 `HeartbeatSeconds`:** 시간을 넘기면 `States.Timeout` 오류를 낸다. 기존 Retry·Catch를 그대로 탄다.
- 멈춘 실행을 어떻게 보관할지 `ponytail:` 주석에 적는다. 메모리에만 두고 재시작하면 잃는다면 그렇게 쓴다.
- 테스트:
  - SQS로 토큰을 받아 SendTaskSuccess를 보내면 실행이 SUCCEEDED가 되어야 한다.
  - 하트비트가 없으면 1초 뒤 Catch로 가야 한다.
  - 엉터리 토큰은 오류가 나야 한다.

## 15일차 (2026-12-09): Lambda 가중치 별칭·한정자별 호출 설정 — ✅ 완료 (`d69a6bc`): AdditionalVersionWeights(1개·0<가중치≤1·버전 달라야)·rand 라우팅·ExecutedVersion, EventInvokeConfig 한정자별 저장($LATEST 상속), 단위/boto3 테스트(49/45)·우분투 두 모드 통과. 확률 테스트(200회 각 30% 이상)는 기준이 느슨함을 보고에 명시
- **`lambda.rs` 3행:** 별칭 `RoutingConfig.AdditionalVersionWeights`를 지원한다. 한 버전만, 가중치는 0~1이다.
  - 호출할 때 `rand`로 버전을 고르고, 응답 `ExecutedVersion`에 실제 버전을 적는다.
  - 지금은 이 설정을 거부하니, 거부 코드를 지운다.
- **`lambda.rs` 536행:** EventInvokeConfig를 한정자(버전·별칭)별로 저장한다. 한정자가 없으면 `$LATEST` 설정을 쓴다.
- 테스트:
  - 가중치 0.5로 200번 호출하면 두 버전이 각각 30% 이상이어야 한다. 확률 테스트라 기준을 느슨하게 잡았다는 사실을 보고에 적는다.
  - 가중치 1.0을 넘으면 거부되어야 한다.
  - 별칭별 OnFailure 대상이 서로 섞이지 않아야 한다.

## 16일차 (2026-12-10): ECS 롤링 배포·헬스 체크 (Docker 필요, 우분투에서만) — ✅ 완료 (`e8c0fff`): deploymentConfiguration 롤링(최소 건강 수 유지·surge 상한)·deployments(PRIMARY/ACTIVE)·rolloutState, healthCheck→docker --health-cmd·unhealthy 교체, 단위/boto3 테스트(49/46)·우분투 두 모드 통과·컨테이너 0개
- **`ecs.rs` 246행:** 서비스 업데이트를 `deploymentConfiguration`(`minimumHealthyPercent`, `maximumPercent`)에 따라 단계적으로 바꾼다.
  - `deployments` 배열(PRIMARY·ACTIVE)과 `rolloutState`를 보여 준다.
- **헬스 체크:** 컨테이너 `healthCheck.command`를 Docker `--health-cmd`로 넘긴다. unhealthy 태스크는 교체한다.
- 컨테이너 수는 우분투 한도(RAM 8 GiB)를 고려해 테스트에서 최대 3개로 둔다. 끝나면 `docker ps -a`가 0개여야 한다.
- 테스트:
  - 2개 태스크 서비스의 태스크 정의를 바꾸는 동안 실행 중인 태스크가 1개 아래로 떨어지지 않아야 한다(min 50%).
  - 실패하는 헬스 체크를 가진 태스크는 교체되어야 한다.

## 17일차 (2026-12-11): RDS 스냅샷·파라미터 그룹 (Docker 필요) — ✅ 완료 (`5874074`): docker commit 스냅샷·복원(데이터를 볼륨 밖 PGDATA/--datadir에 둬서 commit에 잡힘, 기본 이미지 크기 postgres 420MB·mysql 1.12GB), 파라미터 그룹 CRUD·화이트리스트·재부팅 시 재적용, 단위/boto3 테스트(49/47)·우분투 두 모드 통과·컨테이너·스냅샷 이미지 0개
- **`managed.rs` 3행:**
  - 스냅샷: `CreateDBSnapshot`, `DescribeDBSnapshots`, `DeleteDBSnapshot`, `RestoreDBInstanceFromDBSnapshot`
  - 구현은 `docker commit`이 가장 짧다. 이미지 크기를 보고에 적는다. 스냅샷 이미지는 `rocalcloud-snap-` 접두사로 만들고, 리셋·삭제할 때 지운다.
- **파라미터 그룹:** `CreateDBParameterGroup`, `ModifyDBParameterGroup`, `DescribeDBParameters`
  - 적용은 컨테이너 재시작할 때 `-c key=value`(Postgres) 또는 `--key=value`(MySQL)로 한다. 모르는 파라미터는 거부한다.
- 테스트:
  - 테이블에 행을 넣고 스냅샷을 찍은 뒤 복원한 인스턴스에서 그 행이 보여야 한다.
  - `max_connections` 파라미터가 `SHOW`로 확인되어야 한다.
  - 끝나면 남은 컨테이너와 스냅샷 이미지가 0개여야 한다.

## 18일차 (2026-12-12): Route53 헬스 체크·DNS TCP — ✅ 완료 (`590ed38`): TCP/HTTP 루프백 헬스 체크(`Create/Get/List/DeleteHealthCheck`·`GetHealthCheckStatus` `StatusReport`·`ResourcePath` 반영·`serve_health` 중복 스폰 방지)·페일오버/가중치 게이트·DNS TCP(2바이트 길이) 및 UDP >512B TC 절단, 단위/boto3 테스트(50/48)·우분투 두 모드 통과·컨테이너/스냅샷 0개
- **`route53.rs` 4행:** `CreateHealthCheck`, `GetHealthCheck`, `ListHealthChecks`, `DeleteHealthCheck`, `GetHealthCheckStatus`
  - 종류는 TCP와 HTTP이고, **대상은 루프백만 허용한다**(SSRF 방지). 주기는 10초 이상이다.
- 페일오버와 가중치 레코드의 `HealthCheckId`를 반영한다. PRIMARY가 unhealthy면 SECONDARY로 답한다.
- **DNS over TCP:** 기존 UDP 응답 코드를 다시 써서 같은 포트 TCP로도 받는다(2바이트 길이 접두사). 512바이트를 넘는 응답은 UDP에서 TC 비트를 세운다.
- 테스트:
  - 테스트 안에서 루프백 서버를 띄웠다 내리면 페일오버 응답이 바뀌어야 한다.
  - `dnspython` TCP 질의가 되어야 한다.
  - 외부 주소 헬스 체크는 생성할 때 거부되어야 한다.

## 19일차 (2026-12-13): DynamoDB 트랜잭션·스트림·숫자 점검 — ✅ 완료 (`bddd7e2`): 정확한 십진 산술(ADD/SET, 9007199254740993+1 정확·모든 N값 38자리 검사), ClientRequestToken 멱등성·같은 항목 중복 거부·CancellationReasons 위치 확인, DynamoDB Streams 4종 StreamViewType·샤드 반복자·GetRecords(람다 FilterCriteria는 DDB 매핑이 없어 미해당 — 존재하지 않는 기능이라 점검 대상 아님), 단위/boto3 테스트(51/49)·두 모드 통과
- **점검 위주로 한다.** 아래를 테스트로 확인하고, 틀린 것만 고친다.
  - `TransactWriteItems`: 실패할 때 `CancellationReasons` 순서와 코드, `ClientRequestToken` 10분 멱등성, 같은 항목 두 번 지정 거부
  - `TransactGetItems`
  - Streams: `StreamViewType` 4종의 레코드 모양. Lambda 매핑의 `FilterCriteria`가 있으면 그것도 본다.
- **`ddb.rs` 11행:** 키가 아닌 N 값과 `ADD`/`SET a = a + :n` 산술도 십진 문자열로 계산해 정밀도를 지킨다. 3일차의 비교 코드를 다시 쓴다. 38자리를 넘으면 `ValidationException`으로 답한다.
- 테스트:
  - `9007199254740993` + 1이 정확해야 한다.
  - 트랜잭션 조건이 실패하면 `CancellationReasons`에 `ConditionalCheckFailed`가 제 위치에 있어야 한다.
  - 같은 토큰으로 다시 보내면 한 번만 적용되어야 한다.

## 20일차 (2026-12-14): API Gateway REST v1 (1/2) — 리소스·메서드·배포 — ✅ 완료 (`135c086`): `/restapis` CRUD·`/_restapi/{api}/{stage}/` 호출(v1 이벤트 모양·403 Missing Authentication Token), 배포 스냅샷(배포 후 편집 미반영 확인), MOCK 고정 200, AWS/HTTP·requestTemplates 거부, 단위/boto3 테스트(51/50)·두 모드 통과
- **`apigw.rs` 4행:** REST API(`apigateway` 서비스, REST-JSON 프로토콜)를 시작한다.
  - 연산: `CreateRestApi`, `GetResources`, `CreateResource`, `PutMethod`, `PutIntegration`(AWS_PROXY Lambda, MOCK), `PutMethodResponse`, `PutIntegrationResponse`, `CreateDeployment`, `CreateStage`, `Get*`, `Delete*`
- 호출 경로는 `/_restapi/{id}/{stage}/...`이다. HTTP API의 `/_api/`와 같은 처리 방식을 다시 쓴다.
- **REST v1에서는 배포가 실제로 스냅샷을 만든다.** 배포 전 변경은 호출에 보이지 않아야 한다. HTTP API의 "배포는 no-op"과 다른 점을 주석에 적는다.
- 매핑 템플릿(VTL)은 하지 않는다. AWS 통합과 `requestTemplates`는 거부한다.
- 테스트:
  - Lambda 프록시 호출이 200이어야 하고, 이벤트 모양이 REST v1 형식(`resource`, `httpMethod`, `requestContext.stage`)이어야 한다.
  - MOCK은 고정 응답을 돌려주어야 한다.
  - 배포 전 변경은 반영되지 않아야 한다.

## 21일차 (2026-12-15): API Gateway REST v1 (2/2) — 인가자·API 키·CFN — ✅ 완료 (`fdb952f`): COGNITO_USER_POOLS(로컬 풀 JWT)·TOKEN/REQUEST(람다 IAM 정책 해석, Deny 우선·글롭), API 키·사용 계획(토큰 버킷 429, 쿼터는 ponytail), CFN 5종 타입(호출 가능한 스택 템플릿 테스트), 단위/boto3 테스트(51/51)·두 모드 통과
- REST 인가자를 넣는다.
  - `COGNITO_USER_POOLS`: 7일차 JWT 검증 코드를 다시 쓴다.
  - Lambda `TOKEN`, `REQUEST`: IAM 정책 문서 응답을 해석해 Allow·Deny를 판정한다.
- **API 키와 사용 계획:** `CreateApiKey`, `CreateUsagePlan`, `CreateUsagePlanKey`, 메서드 `apiKeyRequired`
  - `x-api-key`가 없으면 403이다.
  - 스로틀은 초당 토큰 버킷 하나만 한다. 쿼터는 `ponytail:` 주석에 한계로 적는다.
- **CFN:** `AWS::ApiGateway::RestApi`, `Resource`, `Method`, `Deployment`, `Stage` 타입을 추가한다.
- 테스트:
  - 키가 없으면 403, 있으면 200이어야 한다.
  - TOKEN 인가자가 Deny를 돌려주면 403이어야 한다.
  - CFN 템플릿 하나로 REST API를 만들어 호출이 되어야 한다.

## 22일차 (2026-12-16): S3 체크섬·트레일러 체크섬 재계산 — ✅ 완료 (`bc9372d`): CRC32/CRC32C 표 기반·SHA-1 손구현(선택 주석)·SHA-256 sha2, PutObject 검증·저장(BadDigest), HeadObject/GetObject(ChecksumMode 헤더, 206 제외)·GetObjectAttributes, 트레일러 값 재계산(VERIFY 모드), 단위/boto3 테스트(51/52)·두 모드 통과
- **`sigv4.rs` 5행:** aws-chunked 트레일러의 `x-amz-checksum-*` 값을 실제로 다시 계산해 비교한다. 다르면 `BadDigest`로 답한다.
  - CRC32와 CRC32C는 표 기반으로 짧게 직접 짠다(새 크레이트 없이). SHA-1은 크레이트가 없으니 거부하거나 직접 짠다. 고른 쪽을 주석에 적는다.
  - SHA-256은 이미 있는 sha2를 쓴다.
- **S3 객체 체크섬:**
  - PutObject의 `x-amz-checksum-*` 헤더와 `ChecksumAlgorithm`을 검증하고 저장한다.
  - `GetObject(ChecksumMode=ENABLED)`와 `HeadObject`에서 돌려준다. `GetObjectAttributes`도 지원한다.
- **SigV4a는 하지 않는다.** ECDSA P-256 크레이트가 새로 필요하다. 필요하면 사용자에게 묻도록 AGENTS.md 7절 후보로만 적는다.
- 테스트:
  - boto3 기본 체크섬(CRC32) 업로드가 통과해야 하고, 변조한 체크섬은 400이어야 한다.
  - `GetObjectAttributes`의 Checksum이 맞아야 한다.
  - 두 모드에서 모두 통과해야 한다. VERIFY_SIGV4 모드에서는 트레일러 경로를 탄다.

## 23일차 (2026-12-17): v0.1.7 릴리스 + 다음 10일 계획 — ✅ 완료 (`16f3202`): 우분투 전체 검증 ALL PASSED(단위 51·경고 0·JS 스위트·두 모드·부분 실패·메모리 +1.19MiB·SQLite·컨테이너 0개), v0.1.7 준비(Cargo·town.html·AGENTS 1/7/8), Playwright 점검 0 에러. 태그 푸시는 계속 사용자 승인 대기 — ✅ 완료·태그 대기 (`893506b`): Cargo 0.1.7·`town.html` 동기화(v0.1.0~v0.1.7, boto3 52)·AGENTS 1/2/7/8절 갱신, 우분투 전체 검증(단위 51·boto3 52 두 모드·JS 8·Rust 7·컨테이너/스냅샷 0개), Playwright 라이브 Pages 점검(HTTP 200·에러 0건). **태그 푸시(v0.1.5/v0.1.6/v0.1.7 정리 포함)는 사용자 승인 대기**
- 우분투 전체 검증을 돌린다(두 모드, JS·Rust 스위트, `ubuntu_verify.sh`, 컨테이너 0개, 스냅샷 이미지 0개).
- v0.1.7을 준비한다. 절차는 1일차 1-2와 같다.
  - **태그 푸시는 사용자 승인을 받은 뒤에만 한다.**
  - 아직 승인을 기다리는 태그(v0.1.5, v0.1.6)가 남아 있으면, 순서대로 낼지 하나로 묶을지 사용자에게 묻는다.
- AGENTS.md 1·7·8절을 갱신하고, `town.html` 12절 숫자를 고친다. Playwright 화면 점검도 한다.
- 24~75일차 계획은 이미 아래에 있다. 지난 결과를 보고 순서나 범위를 고칠 곳이 있으면 고치고, 고친 이유를 한 줄로 적는다.

---

## 24일차 (2026-12-18): ponytail 주석·문서 사실 맞추기 + 군살 감사 — ✅ 완료 (`893506b`): 오래된 `ponytail:` 3건 정리(`managed.rs`·`cfn.rs`·`lambda.rs`), 중복 `inspector::xml_tag` 제거→`s3::tag` 재사용(`wc -l core/src/*.rs`: 18,536→18,531줄, -5줄), AGENTS.md 2/7/8절 사실화, 우분투 전체 검증(경고 0·단위 51·boto3 52 두 모드·JS 8·Rust 7) 통과
- **오래된 ponytail 주석을 고친다.** 이미 구현했는데 주석에는 아직 "없음"으로 남은 것들이 있다(2026-11-27 기준).
  - `managed.rs` 3행: 스냅샷·파라미터 그룹(17일차)
  - `cfn.rs` 4행: exports/imports(11일차)
  - `lambda.rs` 3행: 가중치 별칭(15일차)
  - `sigv4.rs` 5행: 22일차 결과
  - `apigw.rs` 4행: 20~21일차 결과
- `grep -rn ponytail core/src` 전체를 코드와 대조해 주석이 사실과 맞게 한다.
- **군살 감사:** 23일 동안 코드가 많이 늘었다. 각 파일에서 다음을 찾아 지운다. 동작은 바꾸지 않는다.
  - 중복 헬퍼. 예: 서비스마다 따로 만든 XML 태그 읽기, ARN 쪼개기, 시각 형식 변환
  - 쓰지 않는 함수와 필드, 같은 일을 하는 두 경로
  - 빌드 경고 0개, 단위·SDK 테스트 개수 유지를 확인한다.
- AGENTS.md 2절의 구조 설명과 8절의 한계를 실제 코드에 맞춘다.
- **완료 기준:** 줄 수 변화(`wc -l core/src/*.rs` 전후)를 보고하고, 테스트 전부 통과.

## 25일차 (2026-12-19): Lambda 레이어 — ✅ 완료 (`ff6652a`): Publish/Get/GetByArn/List/ListVersions/Delete/Permission 연산, 함수 `Layers`(최대 5·한 레이어 한 버전·없는 버전 거부), 뒤 레이어 우선 PYTHONPATH/NODE_PATH, 경로 탈출 zip 거부, 단위 52·boto3 53(두 모드 통과, 우분투). Node는 require만 NODE_PATH를 따름(ESM bare import 미지원, 주석)
- 연산: `PublishLayerVersion`(zip, CompatibleRuntimes), `GetLayerVersion`, `ListLayers`, `ListLayerVersions`, `DeleteLayerVersion`, `AddLayerVersionPermission`(같은 계정만)
- 함수 `Layers`(최대 5개) 설정을 넣는다.
  - 실행할 때 레이어를 순서대로 풀어 놓는다. 위치는 `/opt` 대신 함수별 임시 디렉터리다.
  - Python은 `python/`을 `PYTHONPATH`에, Node는 `nodejs/node_modules`를 `NODE_PATH`에 넣는다.
  - 풀어 놓은 결과는 레이어 버전별로 캐시한다.
- zip은 이미 있는 `zip` 크레이트로 푼다. **경로 탈출(`../`, 절대 경로)이 있는 항목은 거부한다.**
- 테스트:
  - 레이어에 넣은 모듈을 함수가 import해야 한다.
  - 레이어 순서가 바뀌면 뒤 레이어가 이겨야 한다.
  - 없는 레이어 ARN은 거부되어야 한다.
  - 경로 탈출 zip은 거부되어야 한다.

## 26일차 (2026-12-20): Lambda 웜 실행 (상주 프로세스) — ✅ 완료 (`185f13b`): 함수·버전·수정시각 키의 상주 프로세스 재사용(전역 변수 유지·동시 호출은 풀), stdin/fd1 한 줄 JSON 프로토콜+로그는 결과의 logs 배열(경합 제거, print 조각은 버퍼로 병합), `x-rc-cold-start`·Init Duration 첫 호출만, 유휴 5분 스윕+30초 리퍼, 설정 변경·exit()·타임아웃 교체, 셧다운 잔여 0(`pgrep -f rocalcloud-lambda-warm`), 단위/boto3(52/54)·두 모드 통과
- **`lambda.rs` 3행 "no warm containers":** 호출마다 인터프리터를 새로 띄우지 않고, 함수·버전별 상주 프로세스 하나를 재사용한다.
  - 프로세스와 줄 단위 JSON으로 주고받는 작은 부트스트랩 스크립트를 런타임별로 하나씩 둔다.
- 유휴 5분 뒤 종료한다. 코드·설정·환경 변수가 바뀌면 바로 교체한다. 동시 실행 한도(8개, `lambda.rs` 17행)를 그대로 지킨다.
- 응답에 콜드 스타트 여부를 적는다. 로그의 `Init Duration`을 첫 호출에만 쓴다.
- 함수 전역 변수가 호출 사이에 유지되는 것이 AWS와 같은 동작이다. 이것을 테스트로 고정한다.
- 테스트:
  - 전역 카운터가 두 번째 호출에서 2가 되어야 한다.
  - 설정을 바꾸면 1로 돌아가야 한다.
  - 함수가 `exit()`하면 다음 호출에서 새 프로세스가 떠야 한다.
  - 서버를 종료하면 남은 프로세스가 0개여야 한다.

## 27일차 (2026-12-21): Lambda 컨테이너 이미지 (Docker 필요) — ✅ 완료 (`cf59a8f`): ImageUri(로컬 이미지만, inspect 검증·명확한 오류), docker run -d + RIE POST(최소 HTTP 클라이언트·청크 디코딩·부팅 재시도), `--memory`·host-gateway, 웜 컨테이너 풀(유휴 5분·forget·cold-start·Init Duration), 셧다운 명시적 정리(App 미드롭 대비), 단위/boto3(52/55)·두 모드 통과, 이미지 192MB·첫 호출 402ms·컨테이너 잔여 0
- `PackageType=Image`와 `Code.ImageUri`를 받는다.
  - 이미지는 로컬 Docker에 이미 있는 것만 받는다. ECR 에뮬레이션을 하지 않으니 `docker pull`도 하지 않는다. 없으면 명확한 오류로 답한다.
- 실행은 공식 Lambda 베이스 이미지에 들어 있는 RIE(`/lambda-entrypoint.sh`)를 쓴다. 컨테이너를 127.0.0.1 포트에 열고 `/2015-03-31/functions/function/invocations`로 POST한다.
- 컨테이너도 26일차와 같은 유휴 종료와 동시 실행 한도를 따른다. 메모리는 함수 `MemorySize`로 `--memory` 제한을 건다.
- 테스트 (우분투):
  - 작은 Python 베이스 이미지로 호출이 되어야 한다.
  - 없는 이미지는 오류가 나야 한다.
  - 끝나면 남은 컨테이너가 0개여야 한다.
  - 이미지 크기와 첫 호출 시간을 보고에 적는다.

## 28일차 (2026-12-22): Cognito MFA (TOTP)
- 연산: `AssociateSoftwareToken`, `VerifySoftwareToken`, `SetUserMFAPreference`, `AdminSetUserMFAPreference`, `SetUserPoolMfaConfig`(OFF·OPTIONAL·ON)
- 로그인할 때 `SOFTWARE_TOKEN_MFA` 챌린지를 내고 `RespondToAuthChallenge`로 답을 받는다.
- **TOTP에는 HMAC-SHA1이 필요하다.** SHA-1을 짧게 직접 짠다(약 40줄). `sfn.rs`의 `States.Hash` SHA-1도 같은 함수로 열고, 288행 주석을 고친다. RFC 6238 테스트 벡터로 검증한다.
- SMS MFA는 하지 않는다(문자를 보낼 곳이 없다). 확인 코드는 지금처럼 이벤트로만 낸다.
- 테스트:
  - TOTP를 등록한 뒤 `pyotp` 없이 테스트 안에서 직접 계산한 코드로 로그인이 되어야 한다.
  - 틀린 코드는 `CodeMismatchException`이어야 한다.

## 29일차 (2026-12-23): Cognito SRP (1/2): USER_SRP_AUTH
- `InitiateAuth(AuthFlow=USER_SRP_AUTH)`와 `PASSWORD_VERIFIER` 챌린지를 넣는다. AWS가 쓰는 3072비트 그룹, `k = H(N, g)`, 그리고 `SRP_B`, `SALT`, `SECRET_BLOCK`, `USER_ID_FOR_SRP`를 쓴다.
- **큰 수 연산:** 이미 의존하는 `rsa` 크레이트가 `BigUint`를 다시 내보내는지 먼저 확인한다. 쓸 수 있으면 새 크레이트 없이 간다. 안 되면 사용자에게 묻는다.
- HKDF(sha2 기반)는 짧게 직접 짠다.
- 사용자 저장 방식이 비밀번호 원문이면 SRP 검증값을 같이 저장한다. 스냅샷 호환성을 확인한다.
- 테스트: boto3에는 SRP 도우미가 없으므로 테스트 안에 작은 SRP 클라이언트를 직접 둔다. 공개된 warrant·amazon-cognito-identity-js 계산식을 참고한다.

## 30일차 (2026-12-24): Cognito SRP (2/2) + 사용자 정의 인증 챌린지
- SRP를 마무리한다.
  - `DEVICE_SRP_AUTH`는 거부한다.
  - SRP 흐름에서도 28일차 MFA 챌린지로 이어지게 한다.
  - Amplify JS가 쓰는 흐름으로 JS 스위트(`tests/js`)에 테스트를 하나 넣는다. `@aws-sdk/client-cognito-identity-provider`와 SRP 계산을 쓴다.
- **CUSTOM_AUTH:** `DefineAuthChallenge`, `CreateAuthChallenge`, `VerifyAuthChallengeResponse` Lambda 트리거를 넣는다. 9일차의 트리거 호출 코드를 다시 쓴다.
- `cognito.rs` 4행 주석을 고친다.
- 테스트:
  - 질문과 답 방식의 사용자 정의 챌린지 3단계 흐름이 되어야 한다.
  - 틀린 답 세 번이면 실패해야 한다.

## 31일차 (2026-12-25): Cognito 호스팅 UI·OAuth2 (로컬만)
- `/_cognito/{pool}/oauth2/authorize`, `/login`(최소 HTML 폼), `/oauth2/token`, `/oauth2/userInfo`, `/logout`을 넣는다.
- 지원 흐름은 Authorization code + PKCE(S256)와 `client_credentials`(리소스 서버 scope)다. implicit은 거부한다.
- **보안 조건:**
  - 앱 클라이언트 `CallbackURLs`에 정확히 맞는 `redirect_uri`만 받는다.
  - `state`를 그대로 돌려준다.
  - 코드는 1회용이고 5분 뒤 만료된다.
  - 로그인 폼 POST는 같은 출처만 받는다. 관리 엔드포인트의 `x-rocalcloud` 규칙과는 별개로, 폼에 CSRF 토큰을 넣는다.
- 외부 IdP(Google 등) 연동은 하지 않는다.
- 테스트:
  - requests로 authorize → login POST → code → token 교환까지 가면 id_token이 7일차 JWT 인가자를 통과해야 한다.
  - 틀린 `redirect_uri`, 재사용한 코드, PKCE 불일치는 모두 실패해야 한다.

## 32일차 (2026-12-26): CloudFormation 중첩 스택
- `AWS::CloudFormation::Stack`과 `TemplateURL`을 넣는다.
  - URL은 **로컬 S3 객체만** 받는다(`http://127.0.0.1:4566/bucket/key` 형식이나 `s3://`). 그 밖은 거부한다.
- `Parameters` 전달, `Fn::GetAtt NestedStack.Outputs.X`, 부모를 삭제하거나 롤백할 때 자식도 함께 처리한다. 순환 중첩은 깊이 5에서 거부한다.
- `DescribeStacks`에 `ParentId`·`RootId`를 넣고, GUI 표에 들여쓰기로 보여 준다.
- 테스트:
  - 2단 중첩으로 SQS를 만들고 부모 Outputs에 URL이 보여야 한다.
  - 자식이 실패하면 부모가 롤백되어야 한다.
  - 외부 URL은 거부되어야 한다.

## 33일차 (2026-12-27): CloudFormation SAM 변환
- `Transform: AWS::Serverless-2016-10-31`을 받는다. 지원 타입은 다음이다.
  - `AWS::Serverless::Function`: 이벤트 소스 SQS·SNS·Schedule·Api·HttpApi·Kinesis·DynamoDB
  - `::Api`, `::HttpApi`, `::SimpleTable`, `::LayerVersion`
  - `Globals` 섹션
- 펼친 템플릿은 `GetTemplate(TemplateStage=Processed)`로 볼 수 있게 한다.
- 모르는 SAM 속성은 무시하지 말고 오류로 답한다(흉내 금지 원칙).
- 테스트:
  - 실제 `sam init` 수준의 hello-world 템플릿(코드는 로컬 S3 zip)을 배포해 API 호출과 SQS 트리거가 동작해야 한다.
  - 모르는 속성은 실패해야 한다.

## 34일차 (2026-12-28): CloudFormation 변경 세트·사용자 정의 리소스·드리프트
- **변경 세트:** `CreateChangeSet`(UPDATE·CREATE), `DescribeChangeSet`(Add·Modify·Remove, Replacement True/False — 11일차의 교체 표를 다시 쓴다), `ExecuteChangeSet`, `DeleteChangeSet`, `ListChangeSets`
- **사용자 정의 리소스:** `Custom::X`·`AWS::CloudFormation::CustomResource`의 ServiceToken(Lambda만, SNS는 거부)
  - 응답 URL은 로컬 `/_cfn/response/{token}`이다. 이 POST는 토큰이 인증 수단이라 `x-rocalcloud` 예외로 두고, 그 이유를 주석에 적는다.
  - 1시간이 아니라 60초 안에 응답이 없으면 실패로 본다.
- **드리프트:** `DetectStackDrift`와 `DescribeStackResourceDrifts`를 넣는다. 템플릿 속성과 실제 리소스 속성을 비교한다. 지원 타입은 SQS, SNS, Lambda, DynamoDB뿐이고 나머지는 `NOT_CHECKED`다.
- `cfn.rs` 4행 주석을 고친다.
- 테스트:
  - 변경 세트에 교체 여부가 맞게 나와야 한다.
  - 사용자 정의 리소스 Lambda가 `Data`를 돌려주면 GetAtt로 읽혀야 한다.
  - 큐 속성을 직접 바꾸면 DRIFTED로 나와야 한다.

## 35일차 (2026-12-29): v0.1.8 릴리스 + 중간 점검
- 우분투 전체 검증을 돌린다(두 모드, JS·Rust, `ubuntu_verify.sh`, 컨테이너·이미지 0개).
- **회귀 점검:** `mem_bench.py` 결과를 1일차 기록과 비교한다. 유휴 메모리, 1만 건 처리 메모리, 바이너리 크기가 늘었으면 원인을 적는다. 웜 프로세스(26일차) 때문에 늘었으면 그렇다고 적는다.
- v0.1.8을 준비한다(1일차 1-2 절차). **태그 푸시는 사용자 승인 후에만 한다.** 승인을 기다리는 태그가 쌓여 있으면 하나로 묶을지 묻는다.
- AGENTS.md 1·7·8절과 `town.html` 12절 숫자를 고치고, Playwright 화면 점검을 한다.
- 남은 날(36~53)의 순서를 다시 본다.

## 36일차 (2026-12-30): Lambda 이벤트 소스 매핑 마무리
- **`lambda.rs` 856행:** `TumblingWindowInSeconds`(Kinesis·DynamoDB Streams, `state`와 `isFinalInvokeForWindow`)와 `ParallelizationFactor`(1~10, 같은 파티션 키 순서 유지)를 넣는다.
- **모든 소스 공통:**
  - `FilterCriteria`(EventBridge 패턴 문법 — `events.rs` 매칭 코드를 다시 쓴다)
  - `MaximumBatchingWindowInSeconds`
  - `FunctionResponseTypes=ReportBatchItemFailures`(SQS·Kinesis·DynamoDB)
  - 이미 있는 것은 테스트만 추가한다.
- 테스트:
  - 필터에 맞지 않는 레코드는 함수에 가지 않아야 한다. SQS에서는 삭제되어야 한다(AWS 동작).
  - 부분 실패 응답이면 실패한 항목만 다시 와야 한다.
  - 텀블링 윈도의 state가 누적되어야 한다.

## 37일차 (2026-12-31): SNS http(s) 구독·EventBridge API destinations (루프백만)
- **`sns.rs` 4행·`main.rs` 928행:** `http`·`https` 프로토콜 구독을 넣는다.
  - **엔드포인트는 루프백만 허용한다**(SSRF 방지, 8일차 HTTP_PROXY와 같은 검사 함수를 쓴다). https는 TLS 크레이트가 없으니 거부한다.
  - `SubscriptionConfirmation` 메시지(SubscribeURL·Token)를 보내고, `ConfirmSubscription` 전에는 배달하지 않는다.
  - 배달 재시도 정책(`DeliveryPolicy`)은 단순 고정 간격 3회로 한다.
- **`events.rs` 3행 API destinations:** 같은 루프백 제한으로 연다. 연산은 `CreateConnection`(API_KEY·BASIC 인증 헤더)과 `CreateApiDestination`이다. 그 밖의 주소는 지금처럼 거부한다.
- email·sms는 계속 받기만 하고 보내지 않는다. 주석은 유지한다.
- 테스트:
  - 테스트 안의 루프백 http 서버가 확인 메시지를 받고 SubscribeURL을 호출한 뒤 알림을 받아야 한다.
  - 외부 주소는 거부되어야 한다.
  - API destination이 인증 헤더를 달고 호출되어야 한다.

## 38일차 (2027-01-01): Step Functions Express·Activity
- **Express:** `type=EXPRESS` 상태 기계와 `StartSyncExecution`(`sync-states` 경로, 결과를 바로 돌려줌)을 넣는다. Express에서는 `.sync`와 `.waitForTaskToken` 패턴을 거부한다(AWS 동작).
- **Activity:** `CreateActivity`, `DescribeActivity`, `ListActivities`, `DeleteActivity`, `GetActivityTask`(긴 폴링 최대 60초, 테스트에서는 짧게), Task 상태의 `arn:...:activity:x`. 응답은 14일차 작업 토큰 연산으로 받는다.
- `sfn.rs` 5행 주석을 고친다.
- 테스트:
  - 동기 실행 결과가 바로 와야 한다.
  - 작업자 스레드가 GetActivityTask로 받아 SendTaskSuccess를 보내면 실행이 끝나야 한다.

## 39일차 (2027-01-02): Step Functions 분산 Map·Wait 정확도
- Map 상태의 `ItemReader`를 넣는다. 원본은 로컬 S3 JSON 배열, CSV(헤더 있음), `ListObjectsV2`다.
- `ResultWriter`는 S3에 결과 JSON을 쓴다. `MaxConcurrency`는 지킨다. 자식 실행은 내부에서 돌리고 `ListMapRuns`, `DescribeMapRun`을 넣는다.
- `ToleratedFailurePercentage`와 `ToleratedFailureCount`도 넣는다.
- Wait 상태의 `Timestamp`·`TimestampPath`·`SecondsPath`를 점검한다. 테스트로만 확인하고, 틀리면 고친다.
- 테스트:
  - S3 CSV 100행을 Map으로 처리한 결과가 S3에 써져야 한다.
  - 실패 허용 비율을 넘으면 실패해야 한다.

## 40일차 (2027-01-03): DynamoDB 테이블 변경·PartiQL
- **`ddb.rs` 888행:** `UpdateTable`을 확장한다.
  - `GlobalSecondaryIndexUpdates`(Create·Delete — 생성할 때 기존 항목으로 인덱스를 채운다)
  - `BillingMode` 전환, `StreamSpecification` 켜기·끄기
  - CFN 쪽 교체도 제자리 변경으로 바꾼다(`cfn.rs` 613행).
- **PartiQL:** `ExecuteStatement`, `BatchExecuteStatement`, `ExecuteTransaction`
  - 지원 문법은 `SELECT … FROM t WHERE 키 조건 [AND 필터]`, `INSERT INTO t VALUE {...}`, `UPDATE t SET … WHERE 키`, `DELETE FROM t WHERE 키`, 매개변수 `?`다.
  - 모르는 문법은 `ValidationException`으로 답한다.
  - 파서는 손으로 짠 짧은 토크나이저로 한다.
- 테스트:
  - GSI를 추가한 직후 기존 항목이 Query로 나와야 한다.
  - PartiQL 네 문장이 각각 SDK API 결과와 같아야 한다.

## 41일차 (2027-01-04): S3 수명 주기·버전 관리 점검·CORS
- **수명 주기:** `PutBucketLifecycleConfiguration` — Expiration(Days·Date), NoncurrentVersionExpiration, AbortIncompleteMultipartUpload.
  - 시계 주입이 가능한 정리 루프로 한다(10일차 Kinesis 보존 방식). 전이(Transition)는 저장만 하고 동작하지 않는다는 사실을 주석에 적는다.
- **버전 관리:** 삭제 마커, `ListObjectVersions`, 버전 지정 Get/Delete, 일시 중지 상태를 점검한다. 이미 있는 것은 테스트만 추가한다.
- **버킷 CORS:** `PutBucketCors`와 OPTIONS 사전 요청 응답. 8일차 API Gateway CORS 코드를 공용으로 뺄 수 있으면 뺀다.
- 테스트:
  - 주입한 시계로 하루를 넘기면 객체가 사라져야 한다.
  - 삭제 마커 뒤 이전 버전을 Get할 수 있어야 한다.
  - CORS 사전 요청 허용과 거부가 맞아야 한다.

## 42일차 (2027-01-05): S3 사전 서명 POST·정적 웹사이트·대용량 스트리밍
- **사전 서명 POST:** `generate_presigned_post` 폼 업로드와 정책 문서 검증을 넣는다. 검증 항목은 만료, `content-length-range`, `starts-with`, 서명이다.
- **정적 웹사이트:** `PutBucketWebsite`(IndexDocument·ErrorDocument·RoutingRules 일부)와 `/_website/{bucket}/...` 경로다. 127.0.0.1에서만 연다.
- **`main.rs` 1468행 256 MiB 한도:** S3 PutObject와 UploadPart 본문을 메모리에 쌓지 않고 임시 파일로 스트리밍하는 방안을 검토한다.
  - 작게 고칠 수 있으면 고친다. 우분투에서 1 GiB 업로드 메모리를 잰다. 작업당 8 GiB 한도 안이다.
  - 구조를 크게 바꿔야 하면 하지 않고 7절 후보로만 적는다.
- 테스트:
  - 정책 안 업로드는 성공하고 범위를 넘으면 실패해야 한다.
  - 웹사이트 인덱스와 404 문서가 동작해야 한다.

## 43일차 (2027-01-06): IAM 다중 값 컨텍스트·권한 경계·세션 정책
- **`iam.rs` 118행:** 컨텍스트 값을 여러 값을 담을 수 있게 바꾼다(`aws:TagKeys`, `aws:PrincipalTag/*`, `s3:prefix` 등). ForAnyValue와 ForAllValues가 진짜 집합 의미로 동작하게 한다. 바꾸는 범위는 최소로 한다.
- **권한 경계:** `PutUserPermissionsBoundary`, `PutRolePermissionsBoundary`. 판정 = 신원 정책 ∩ 경계다.
- **세션 정책:** `AssumeRole`의 `Policy`·`PolicyArns`. 판정 = 역할 정책 ∩ 세션 정책이다.
- **태그 조건:** `aws:ResourceTag/*`(리소스 태그가 있는 서비스만)와 `aws:RequestTag/*`.
- 테스트:
  - 경계 밖 권한은 신원 정책이 허용해도 거부되어야 한다.
  - 세션 정책으로 좁힌 키는 좁혀진 권한만 가져야 한다.
  - ForAllValues 태그 키 집합이 맞게 판정되어야 한다.
  - 기존 IAM 테스트가 전부 그대로 통과해야 한다.

## 44일차 (2027-01-07): v0.1.9 릴리스 + 보안 점검일
- **보안 점검:** 지금까지 추가한 외부 표면을 하나씩 확인한다. 결과는 표로 남긴다.
  - 루프백 검사: HTTP_PROXY, SNS http, API destinations, 헬스 체크, CFN TemplateURL, 컨테이너 포트 바인딩
  - CSRF: 관리 POST의 `x-rocalcloud`, 호스팅 UI 폼 토큰, CFN 응답 URL 예외
  - CORS: `/_events`가 Pages 출처만 받는지, `town_view` allowlist
  - zip과 경로 탈출: Lambda 코드, 레이어, 스냅샷, `RC_STATE_FILE`
  - 이벤트에 비밀이 새는지: 비밀번호, TOTP 시드, OAuth 코드, 세션 키
  - `/code-review` 같은 도구가 있으면 쓰되 max·ultra 단계는 쓰지 않는다. 사용자 지시가 없기 때문이다.
- 발견한 문제는 그날 고친다. 크면 다음 날 맨 앞에 넣는다.
- 검사관 시나리오에 새 보안 시나리오를 2~4개 추가한다(외부 주소 거부, OAuth 재사용, 경계 우회 등).
- v0.1.9를 준비한다. **태그는 승인 후에만 푸시한다.**

## 45일차 (2027-01-08): EC2 NACL·태그
- **`net.rs` 2행:** 네트워크 ACL을 넣는다.
  - 연산: `CreateNetworkAcl`, `CreateNetworkAclEntry`(규칙 번호 순서, allow·deny, 상태 없음 — 응답 방향도 따로 판정), `ReplaceNetworkAclAssociation`, `DescribeNetworkAcls`
  - 기본 ACL은 전부 허용이다.
- `/_admin/reach` 도달성 판정에 NACL을 넣는다. 어느 규칙에서 막혔는지 이유에 적는다.
- **태그:** EC2 리소스에 `CreateTags`, `DeleteTags`, `DescribeTags`, Describe*의 `tag:Key` 필터를 넣는다.
- 테스트:
  - 보안 그룹은 허용하지만 NACL이 거부하면 도달성이 false이고 이유에 NACL 규칙 번호가 있어야 한다.
  - 응답 포트 범위 규칙이 빠지면 거부되어야 한다.

## 46일차 (2027-01-09): EC2 VPC 피어링·NAT·인터넷 게이트웨이 경로
- `CreateVpcPeeringConnection`과 `AcceptVpcPeeringConnection`, 라우트 테이블 `CreateRoute`(대상 pcx, igw, nat), `CreateNatGateway`를 넣는다.
- 도달성 판정을 VPC 사이로 넓힌다. 피어링과 라우트가 양쪽에 다 있어야 통한다. 겹치는 CIDR 피어링은 거부한다.
- 인터넷 방향 도달성: 퍼블릭 서브넷(igw 경로)과 프라이빗 서브넷의 나가는 방향(nat 경로)을 구분해 답한다. 실제 패킷은 없다는 사실을 주석에 적는다.
- 마을에 VPC 사이 다리를 표시할 수 있으면 넣는다.
- 테스트:
  - 피어링을 수락하기 전에는 false, 수락하고 라우트를 넣으면 true여야 한다.
  - 한쪽 라우트가 빠지면 false여야 한다.
  - 프라이빗 서브넷은 들어오는 인터넷이 false여야 한다.

## 47일차 (2027-01-10): ALB 연결 재사용·가중치·고정 응답
- **`elb.rs` 6행:** 규칙이 있는 리스너에서도 keep-alive를 유지한다.
  - HTTP/1.1 요청 경계를 `Content-Length`와 chunked로 직접 파싱해 요청마다 다시 라우팅한다.
  - 이것이 너무 커지면 지금 방식(`Connection: close`)을 유지하고 이유를 적는다.
- **액션:** `forward`의 여러 대상 그룹 가중치(`ForwardConfig.TargetGroups`), `fixed-response`, `redirect`(루프백 안)를 넣는다.
- **스티키 세션:** 대상 그룹 속성 `stickiness.enabled`와 `AWSALB` 쿠키를 넣는다.
- **Lambda 대상:** `TargetType=lambda`로 ALB 이벤트 형식을 넣는다.
- TLS 리스너는 rustls가 필요하므로 사용자에게 묻는다. 답이 없으면 하지 않는다.
- 테스트:
  - 한 연결로 경로가 다른 두 요청이 서로 다른 대상에 가야 한다.
  - 가중치 0과 100을 확인한다.
  - 고정 응답의 본문과 코드가 맞아야 한다.
  - 같은 쿠키면 같은 대상이어야 한다.
  - Lambda 대상 응답이 와야 한다.

## 48일차 (2027-01-11): Kinesis enhanced fan-out
- `RegisterStreamConsumer`, `DescribeStreamConsumer`, `ListStreamConsumers`, `DeregisterStreamConsumer`, 그리고 `SubscribeToShard`를 넣는다.
  - `SubscribeToShard`는 HTTP/2 + `application/vnd.amazon.eventstream`, 이벤트 스트림 프레이밍(prelude CRC32 — 22일차 CRC32 재사용)이다.
- **HTTP/2가 먼저다.** axum과 hyper가 h2를 켜고 있는지 확인한다. 기능 플래그만으로 되면 진행한다. 새 크레이트가 필요하면 사용자에게 묻는다. 안 되면 등록 연산만 넣고 Subscribe는 명확한 오류로 답한다.
- 구독은 5분 뒤 끝난다(AWS 동작). 테스트에서는 짧게 한다.
- 테스트: Rust SDK 스위트에서 SubscribeToShard로 레코드 2개를 받아야 한다. boto3도 되면 같이 넣는다.

## 49일차 (2027-01-12): KMS 키 정책·grant·회전 (진짜 암호는 승인 시)
- **`kms.rs` 2행:**
  - 키 정책: `PutKeyPolicy`, `GetKeyPolicy`. 기본 정책은 계정 루트 허용이다. 리소스 정책 평가기는 이미 있는 것을 다시 쓴다.
  - grant: `CreateGrant`, `ListGrants`, `RetireGrant`, `RevokeGrant`, 연산 제한
  - `EnableKeyRotation`과 `RotateKeyOnDemand`: 이전 키 재료로 만든 암호문도 복호화되어야 한다.
  - `GenerateDataKeyPair`
- **진짜 암호(AES-GCM):** aes-gcm 크레이트가 필요하다. 이날 시작할 때 사용자에게 묻고, 승인을 받으면 바꾼다. 바꿀 때는 기존 스냅샷의 옛 형식 암호문을 계속 복호화할 수 있게 버전 바이트를 둔다.
- SSM SecureString(`ssm.rs` 28행)과 Secrets Manager가 KMS 키를 따르게 맞춘다.
- 테스트:
  - 키 정책 Deny가 Decrypt를 막아야 한다.
  - grant로만 허용된 역할이 Decrypt할 수 있어야 한다.
  - 회전한 뒤 옛 암호문도 복호화되어야 한다.

## 50일차 (2027-01-13): RDS·ElastiCache 복제본 (Docker 필요)
- **`managed.rs` 3행:**
  - RDS 읽기 복제본: `CreateDBInstanceReadReplica`. Postgres 스트리밍 복제나 MySQL 복제를 컨테이너 두 개로 만든다. 복제본은 읽기 전용이다.
  - `PromoteReadReplica`를 넣는다.
  - ElastiCache 복제 그룹: `CreateReplicationGroup`(Redis 주·복제 각 1개), `DescribeReplicationGroups`의 엔드포인트 2종.
- **컨테이너 수와 메모리 한도에 주의한다.** 테스트에서는 동시에 최대 4개만 띄운다. 각 컨테이너에 `--memory 512m`를 건다.
- 테스트:
  - 주 DB에 쓴 행이 복제본에서 몇 초 안에 읽혀야 한다.
  - 복제본에 쓰면 실패해야 한다.
  - Redis 복제본이 주 값을 읽어야 한다.
  - 끝나면 남은 컨테이너가 0개여야 한다.

## 51일차 (2027-01-14): 성능·메모리 점검일
- 우분투에서 `mem_bench.py`를 돌리고 다음을 잰다. 결과는 AGENTS.md에 표로 남긴다.
  - 서비스별 요청 처리량(동시 8, 30초)
  - 장시간 실행(1시간) 메모리 추이
- **DynamoDB:** `ddb.rs` 800행은 Query가 선형 탐색이다. 10만 항목에서 Query 지연이 100 ms를 넘으면 정렬 키를 `BTreeMap`으로 바꾼다. 넘지 않으면 그대로 두고 수치를 주석에 적는다.
- **이벤트 링 버퍼(`app.recent` 1000건)와 SSE 브로드캐스트:** 느린 구독자가 있을 때 메모리가 늘지 않는지 확인한다.
- **CPU 한도:** 웜 Lambda 프로세스, 컨테이너, 헬스 체크 루프가 모두 켜진 상태에서 8스레드를 넘지 않는지 확인한다.
- 고칠 것이 있으면 그날 고친다. 큰 것은 7절에 적는다.

## 52일차 (2027-01-15): 문서·예제·마을 대청소
- **README:** 서비스별 지원 범위 표를 실제와 맞추고, 빠른 시작 예제를 실행해 확인한다.
- **`SKILL.md`, `CONTRIBUTING.md`:** 새 패턴을 반영한다. 레이어, 웜 실행, 루프백 검사 함수, 시계 주입 같은 것이다.
- **`local-cloud-emulator-plan.md`:** 체크리스트에 이후 추가분을 덧붙인다.
- **`town.html`:**
  - 연대기 섬에 24~51일차 이정표를 넣는다.
  - 새 서비스·기능의 건물 표시를 넣는다: 레이어, Cognito 호스팅 UI, NACL, 피어링 다리.
  - 숫자를 고친다.
  - Playwright로 Pages 마을, `/_town`, `/_ui`를 확인한다. 콘솔 에러는 0개여야 한다.
- **`ui.html`:** 늘어난 표가 화면을 넘치지 않는지 본다. 좁은 폭(휴대폰)도 확인한다.

## 53일차 (2027-01-16): v0.2.0 릴리스 + 새 크레이트 승인 묻기
- 우분투 전체 검증을 돌린다(두 모드, JS·Rust, `ubuntu_verify.sh`, 컨테이너·이미지 0개).
- **v0.2.0을 준비한다.** **태그는 승인 후에만 푸시한다.** Homebrew sha256을 반영하고, 리눅스 바이너리로 확인한다.
- **회고:** 다음 세 가지를 이 문서 끝 "회고" 절에 적는다.
  - 계획 대비 완료, 일부, 못 함 개수
  - 사용자 승인을 기다리는 항목
  - 테스트하지 않은 경로
- **67~69일차를 위해 새 크레이트 세 개를 한 번에 묻는다.**
  - `aes-gcm`: KMS 진짜 암호
  - `p256`: SigV4a, DNSSEC 서명
  - `rustls`(+`rcgen`): ALB·API TLS
  - 각각 바이너리 크기 증가를 우분투에서 재서 함께 보여 준다.
  - 답에 따라 67~69일차를 "구현"으로 할지 "대안과 명확한 거부"로 할지 정한다.

---

## 54일차 (2027-01-17): 작은 한계 묶음: cron L/W/#·Logs 필터·DynamoDB 크기
- **`events.rs` cron:**
  - `L`: 일 필드에서는 말일, 요일 필드에서는 `5L`(마지막 금요일)이다.
  - `W`: `15W`는 가장 가까운 평일이다.
  - `#`: `MON#2`는 둘째 월요일이다.
  - `cron_next`를 확장하고, 각각 윤년과 월 경계 단위 테스트를 넣는다. 지금은 거부하니 거부 코드와 주석을 지운다.
- **`logs.rs` 31행:** 필터 패턴 나머지를 지원한다.
  - 공백 구분 필드 패턴 `[ip, user, ..., status=4*]`
  - JSON 패턴의 `&&`, `||`, 괄호, `IS NULL`, `NOT EXISTS`
  - 지원 범위를 주석에 정확히 적는다.
- **`ddb.rs` 400 KB:** 항목 크기를 AWS 규칙으로 계산한다.
  - 속성 이름 길이 + 값 크기다.
  - N은 (유효 자릿수/2)+1바이트, B는 원래 바이트, 리스트와 맵은 원소당 1바이트를 더한다.
  - 경계 테스트: 정확히 400 KB는 통과, 1바이트를 넘으면 실패다.

## 55일차 (2027-01-18): S3 목록 토큰·XML 읽기·IPv6 마을 연결
- **`s3.rs` 326행:** 이어받기 토큰이 "가장 큰 문자 붙이기" 방식이다.
  - 마지막으로 돌려준 키(또는 공통 접두사)를 base64로 담는 정확한 토큰으로 바꾼다.
  - `StartAfter`, `ContinuationToken`, delimiter를 섞은 경우를 10일차 경계 테스트에 더한다.
- **`s3.rs` 116행:** 문자열 스캔 XML 리더를 점검한다.
  - CDATA, 엔티티(`&amp;`, `&lt;`, `&#x..;`), 네임스페이스 접두사가 있는 DeleteObjects와 CompleteMultipartUpload 본문이 처리되는지 테스트한다.
  - 틀리면 고친다. XML 크레이트는 넣지 않는다.
- **IPv6 `?api=[::1]`(AGENTS 7절 8번):**
  - CSP `connect-src`에 `http://[::1]:*`를 넣어 보고 Chrome·Firefox·Safari(우분투 Playwright webkit)에서 확인한다.
  - 되면 허용한다. 안 되면 "CSP 한계로 미지원"을 확정하고 문서에 적는다.
  - 어느 쪽이든 7절 8번을 닫는다.

## 56일차 (2027-01-19): Step Functions JSONata (1/2): 식 평가기
- `QueryLanguage: "JSONata"`(상태 기계 전체 또는 상태별)를 받는다.
- 식은 `{% ... %}` 안에 쓴다. 손으로 짠 작은 JSONata 평가기를 둔다. 지원 범위는 다음이다.
  - 경로: `$states.input.a.b`, 배열 인덱스, 필터 `[cond]`
  - 연산자: 산술, 비교, `and`, `or`, `&`(문자열 연결), 삼항 `? :`
  - 리터럴: 객체·배열 생성자
- **범위 밖 문법(함수 정의, 정규식, 부모 연산자 등)은 `States.QueryEvaluationError`로 명확히 거부한다.**
- 테스트: 평가기 단위 테스트 30개 이상. 공식 문서 예제를 그대로 옮긴다.

## 57일차 (2027-01-20): Step Functions JSONata (2/2): Arguments·Output·Assign
- JSONata 모드의 상태 필드를 넣는다.
  - `Arguments`, `Output`, `Assign`(변수, `$name`으로 참조, 상태 사이 범위 규칙)
  - Choice의 `Condition`
  - `Items`(Map)
- 내장 함수 `$partition`, `$range`, `$hash`, `$random`, `$uuid`, `$parse`와 기본 함수 `$string`, `$number`, `$count`, `$sum`, `$map`, `$filter`, `$keys`, `$merge`를 넣는다.
- JSONPath 모드의 `Assign` 변수도 같이 지원한다(AWS가 2024년에 추가했다).
- `sfn.rs` 5행의 "no JSONata" 주석을 고친다.
- 테스트:
  - JSONata 상태 기계로 Lambda를 호출하고 결과를 가공해야 한다.
  - `Assign` 변수가 다음 상태에서 보여야 한다.
  - 범위 밖 문법은 실패해야 한다.

## 58일차 (2027-01-21): ECS (1/2): 볼륨·비밀·환경 파일 (Docker)
- 태스크 정의 `volumes`(host `sourcePath`, Docker 볼륨)와 컨테이너 `mountPoints`를 넣는다.
  - **host 경로는 설정한 허용 디렉터리 안만 받는다**(기본값은 rocalcloud 임시 디렉터리). 임의 경로 마운트는 위험하다.
- 컨테이너 `secrets`(Secrets Manager ARN과 JSON 키, SSM 파라미터)를 실행할 때 환경 변수로 주입한다.
  - **값은 이벤트와 `DescribeTasks`에 절대 나오지 않게 한다.**
- `environmentFiles`(로컬 S3 객체)도 넣는다.
- 테스트:
  - 볼륨에 쓴 파일이 같은 태스크의 다른 컨테이너에서 보여야 한다.
  - 비밀 값이 컨테이너 안 `env`에는 있고 이벤트 스트림에는 없어야 한다.
  - 허용 밖 경로는 거부되어야 한다.

## 59일차 (2027-01-22): ECS (2/2): 서킷 브레이커·서비스 검색·용량 공급자
- **`deploymentCircuitBreaker`**(enable, rollback): 새 태스크가 계속 실패하면 배포를 FAILED로 표시하고, rollback이면 이전 태스크 정의로 되돌린다.
- **서비스 검색:** Cloud Map 최소 기능을 넣는다.
  - 연산: `CreatePrivateDnsNamespace`, `CreateService`, `DiscoverInstances`
  - 서비스의 `serviceRegistries`로 태스크 IP를 등록한다.
  - Route53 DNS 서버에서 `svc.namespace`가 풀리게 한다(18일차 DNS 재사용).
- **용량 공급자:** `capacityProviderStrategy`는 저장하고 보여만 준다. Fargate와 EC2를 구분해 실행하지는 않는다는 사실을 주석에 적는다.
- `ecs.rs` 3행 주석을 고친다.
- 테스트:
  - 항상 죽는 이미지로 배포하면 롤백되어야 한다.
  - `DiscoverInstances`와 DNS 질의가 실행 중인 태스크를 돌려주어야 한다.

## 60일차 (2027-01-23): Aurora (1/2): DB 클러스터 (Docker)
- `CreateDBCluster`(aurora-postgresql, aurora-mysql), `CreateDBInstance(DBClusterIdentifier=…)`로 writer와 reader를 붙인다.
- `DescribeDBClusters`의 `Endpoint`(writer)와 `ReaderEndpoint`를 넣는다. reader 엔드포인트는 reader 인스턴스로 순환한다(50일차 복제 재사용).
- `DeleteDBCluster`(인스턴스가 남아 있으면 거부, `SkipFinalSnapshot`)도 넣는다.
- **컨테이너는 최대 3개(writer 1 + reader 2), 각 `--memory 512m`이다.**
- 테스트:
  - writer에 쓴 값이 reader 엔드포인트로 읽혀야 한다.
  - reader에 쓰면 실패해야 한다.
  - 끝나면 남은 컨테이너가 0개여야 한다.

## 61일차 (2027-01-24): Aurora (2/2): 장애 조치·클러스터 스냅샷·Data API
- `FailoverDBCluster`: reader 하나를 승격하고 writer 엔드포인트가 바뀐다.
- 클러스터 스냅샷 `CreateDBClusterSnapshot`과 `RestoreDBClusterFromSnapshot`을 넣는다. 17일차 `docker commit` 방식을 쓴다.
- **RDS Data API**(`rds-data`): `ExecuteStatement`, `BatchExecuteStatement`, `BeginTransaction`, `CommitTransaction`, `RollbackTransaction`
  - 인증은 Secrets Manager 비밀 ARN으로 한다.
  - 클러스터의 `EnableHttpEndpoint`가 켜져 있어야 한다.
  - 결과의 `records` 형식(`stringValue`, `longValue` 등)을 맞춘다.
  - DB 연결은 이미 있는 테스트 도구가 아니라 코어 안에서 컨테이너의 `psql`·`mysql` CLI를 `docker exec`으로 부르는 가장 짧은 방법을 쓴다. 한계는 주석에 적는다.
- `managed.rs` 3행 주석을 고친다.
- 테스트:
  - 장애 조치 뒤 새 writer에 쓸 수 있어야 한다.
  - Data API로 INSERT, SELECT, 트랜잭션 롤백이 되어야 한다.

## 62일차 (2027-01-25): v0.2.1 릴리스 + 중간 점검
- 우분투 전체 검증, `mem_bench` 비교(35일차, 51일차 값과)를 한다.
- v0.2.1을 준비한다(1일차 1-2 절차). **태그는 승인 후에만 푸시한다.**
- AGENTS.md 1·7·8절과 `town.html` 숫자를 고치고, Playwright로 점검한다.
- 63~75일차 순서를 다시 본다. 53일차 새 크레이트 답변에 맞춰 67~69일차를 확정한다.

## 63일차 (2027-01-26): EventBridge Pipes
- `CreatePipe`, `DescribePipe`, `ListPipes`, `UpdatePipe`, `StartPipe`, `StopPipe`, `DeletePipe`를 넣는다.
- 구성:
  - 소스: SQS, Kinesis, DynamoDB Streams. 기존 매핑 폴러 코드를 다시 쓴다.
  - `FilterCriteria`: 36일차 코드
  - 보강: Lambda, Step Functions Express(38일차)
  - 대상: `send_to_target`이 지원하는 것 전부
  - `InputTemplate`: 2일차 InputTransformer 코드
- 실행 역할(`RoleArn`)로 소스를 읽고 대상에 쓸 권한을 `ENFORCE_IAM`일 때 판정한다.
- 테스트:
  - SQS → 필터 → Lambda 보강 → SNS→SQS 끝까지 메시지가 가공되어 도착해야 한다.
  - 필터에 맞지 않는 메시지는 버려져야 한다.
  - Stop하면 흐르지 않아야 한다.

## 64일차 (2027-01-27): SES 템플릿·수신 규칙
- **템플릿:** `CreateTemplate`, `GetTemplate`, `UpdateTemplate`, `DeleteTemplate`, `ListTemplates`, `SendTemplatedEmail`, `SendBulkTemplatedEmail`, `TestRenderTemplate`. v2 `SendEmail(Content.Template)`도 넣는다.
  - `{{var}}`를 치환하고, 빠진 변수는 렌더링 실패로 처리한다.
- **보낸 메일 확인:** 보낸 메일은 지금처럼 실제로 발송하지 않고 `/_ses/sent`(GET)로 보여 준다.
  - 이미 비슷한 것이 있으면 그것을 쓴다.
  - **이벤트 스트림 allowlist에 본문이 새지 않는지 확인한다.**
- **수신 규칙:** `CreateReceiptRuleSet`, `CreateReceiptRule`, `SetActiveReceiptRuleSet`
  - 수신은 `/_ses/inbound`에 POST한 RFC 822 메시지로 흉내 낸다. 관리 POST이므로 `x-rocalcloud` 헤더를 요구한다.
  - 동작: S3 저장, SNS 알림, Lambda 호출
- 테스트:
  - 템플릿 메일이 `/_ses/sent`에서 치환된 상태로 보여야 한다.
  - 수신 메일이 S3에 저장되고 Lambda가 호출되어야 한다.

## 65일차 (2027-01-28): Route53 영역 전송·DNSSEC API
- **AXFR 영역 전송:** 18일차 DNS TCP에 넣는다. **127.0.0.1에서 온 요청만 받는다.**
- **DNSSEC API:** `EnableHostedZoneDNSSEC`, `DisableHostedZoneDNSSEC`, `GetDNSSEC`, `CreateKeySigningKey`(KMS 키 참조)
  - 53일차에 `p256` 승인을 받았으면 실제 RRSIG·DNSKEY 서명을 넣는다(ECDSAP256SHA256).
  - 승인이 없으면 API 상태만 관리하고, 응답에 서명하지 않는다는 사실을 `GetDNSSEC` 상태 메시지와 주석에 명확히 적는다.
- `route53.rs` 4행 주석을 고친다.
- 테스트:
  - `dnspython` AXFR로 레코드 전체가 와야 한다.
  - DNSSEC 켜기·끄기 상태가 바뀌어야 한다.
  - 승인한 경우 `dig +dnssec`에 해당하는 질의에 RRSIG가 있어야 한다.

## 66일차 (2027-01-29): CloudFormation 롤백 복원·남은 교체 속성
- **`cfn.rs` 793행:** 업데이트가 실패하면 교체된 리소스를 이전 속성으로 되돌린다.
  - 교체 업데이트는 "새로 만들기 → 성공하면 옛것 삭제" 순서로 바꾼다. AWS 방식이다.
  - 그러면 롤백은 새것만 지우면 된다.
- **`cfn.rs` 613행:** DynamoDB 빌링 모드와 GSI(40일차 UpdateTable 재사용), S3 속성(버전 관리, 수명 주기, CORS, 알림)을 제자리 변경으로 바꾼다.
- 테스트:
  - 일부러 실패하는 업데이트 뒤 원래 큐 URL과 속성이 그대로여야 한다.
  - 버킷 버전 관리를 바꿔도 버킷 객체가 유지되어야 한다.

## 67일차 (2027-01-30): KMS 진짜 암호 (aes-gcm 승인 시) / 비대칭 키 (승인 없어도)
- **승인한 경우:** 대칭 키 암호문을 AES-256-GCM으로 바꾼다.
  - 포맷은 `버전 바이트 | 키 ID | nonce | 암호문 | 태그`다.
  - 옛 MD5-XOR 암호문도 복호화되게 한다(스냅샷 호환).
  - `EncryptionContext`는 AAD로 쓴다.
  - SSM SecureString(`ssm.rs` 28행)도 실제 KMS 암호문으로 바꾼다.
- **승인이 없어도 하는 것:** 이미 있는 `rsa` 크레이트로 비대칭 키를 넣는다.
  - `CreateKey(KeySpec=RSA_2048/3072/4096, KeyUsage=SIGN_VERIFY|ENCRYPT_DECRYPT)`
  - `Sign`/`Verify`(RSASSA_PSS·PKCS1 SHA-256/384/512), `GetPublicKey`, RSA `Encrypt`/`Decrypt`(OAEP)
- `kms.rs` 2행 주석을 결과에 맞게 고친다.
- 테스트:
  - `GetPublicKey`로 받은 공개 키로 Python `cryptography`가 서명을 검증해야 한다. 테스트 의존성 추가이므로 `uv --with`로만 쓴다.
  - 컨텍스트가 다르면 Decrypt가 실패해야 한다(승인 시).

## 68일차 (2027-01-31): SigV4a (p256 승인 시) / 명확한 거부
- **승인한 경우:** `AWS4-ECDSA-P256-SHA256`을 넣는다.
  - 접근 키에서 ECDSA 키를 유도한다(AWS의 KDF: HMAC-SHA256 카운터 모드, 키가 n-2보다 작을 때까지).
  - `X-Amz-Region-Set`을 처리한다.
  - 헤더 서명과 사전 서명 URL을 모두 지원한다.
  - `VERIFY_SIGV4=1`일 때만 검증한다.
- **승인이 없는 경우:** SigV4a 요청은 `VERIFY_SIGV4=1`일 때 `SignatureDoesNotMatch` 대신 "SigV4a is not supported locally"라는 분명한 오류로 답한다. 기본 모드에서는 지금처럼 서명을 읽지 않고 통과시킨다.
- `sigv4.rs` 5행 주석을 고친다.
- 테스트: Rust SDK나 botocore의 SigV4a 서명기로 S3 다중 리전 접근점처럼 서명한 요청을 보낸다. botocore는 `awscrt`가 있어야 한다. 승인한 경우에만 이 테스트를 넣는다.

## 69일차 (2027-02-01): TLS 리스너 (rustls 승인 시) / 명확한 거부
- **승인한 경우:**
  - ALB `Protocol=HTTPS` 리스너를 넣는다. 인증서는 ACM 최소 기능(`ImportCertificate`)이나 `rcgen` 자체 서명 `RequestCertificate`를 쓴다.
  - API Gateway와 에뮬레이터 자체의 `https://127.0.0.1:4567` 선택 포트도 넣는다(`RC_TLS=1`).
  - HTTP_PROXY의 https 대상과 SNS https 구독도 연다. 둘 다 루프백만 허용한다.
- **승인이 없는 경우:** HTTPS 리스너 생성은 `UnsupportedProtocol`로 명확히 거부한다. 문서에 "TLS는 리버스 프록시(caddy 등)로 앞단에서"라는 안내를 적는다.
- `elb.rs` 6행과 `apigw.rs` 199행 주석을 고친다.
- 테스트(승인 시): 자체 서명 인증서를 `verify=False`로 받아 HTTPS 리스너를 거쳐 대상에 도착해야 한다. 그렇지 않으면 거부 경로만 테스트한다.

## 70일차 (2027-02-02): "하지 않는 것" 정리 + 미지원 연산 전수 점검
- **명확한 거부로 확정할 것:** 각 항목에 `ponytail:`이 아닌 `// unsupported:` 주석과 문서 표를 남긴다.
  - SNS email·sms 발송: 저장만 하고, 보낸 내용은 `/_ses/sent`처럼 확인 엔드포인트에서 본다.
  - Cognito 외부 IdP
  - EC2 인스턴스 실제 실행(`net.rs` 2행)
  - Lambda 동시 실행 8개 한도(`lambda.rs` 17행은 장비 한도라 유지)
  - 256 MiB 본문 한도(42일차 결과에 따라)
- **전수 점검 스크립트:** `tools/op_coverage.py`
  - botocore 서비스 모델에서 지원 서비스의 모든 연산 이름을 뽑는다.
  - 각 연산을 빈 인자로 한 번씩 호출해 응답을 분류한다: 구현됨, 검증 오류, `UnknownOperation`, 500, 연결 끊김.
  - **500과 연결 끊김은 0개여야 한다.** 나오면 고친다.
  - 결과 표(서비스별 구현 연산 수/전체)를 README에 넣는다.
- 테스트: 스크립트 자체가 테스트다. CI에는 넣지 않고 우분투에서만 돌린다(시간이 걸린다).

## 71일차 (2027-02-03): ponytail 0 확인 + 군살 감사 2차
- `grep -rn ponytail core/src`에는 장비 한도처럼 의도해 남기는 것만 있어야 한다. 남은 것은 각각 구현, `unsupported:` 전환, 유지 사유 중 하나로 정리한다.
- **군살 감사 2차(24일차 방식):** 서비스마다 반복되는 다음 코드를 `main.rs`나 작은 공용 모듈로 모은다.
  - 루프백 검사
  - 시계 주입
  - 폴러
  - 배달 재시도
- 동작은 바꾸지 않는다. 줄 수 변화를 보고한다.
- 빌드 경고 0개, 전체 테스트 통과를 확인한다.

## 72일차 (2027-02-04): 도구 호환성: Terraform·CDK·SAM CLI (설치는 승인 후)
- 우분투에 `terraform`, `aws-cdk`(npm), `sam` CLI를 설치해도 되는지 사용자에게 묻는다. 새 패키지 설치이기 때문이다.
- **승인한 경우:** 다음이 에뮬레이터에서 끝까지 되는지 확인한다.
  - Terraform AWS provider(`endpoints` 블록): S3, SQS, Lambda, DynamoDB, IAM, API GW 예제의 `apply`·`destroy`
  - CDK `cdk deploy`: CFN 경로. bootstrap 스택이 되는지 본다.
  - `sam deploy`
- 막히는 연산을 고친다. 하루에 못 끝나면 목록으로 남긴다.
- **승인이 없는 경우:** CFN 템플릿 수준에서 CDK가 만드는 템플릿(`cdk synth` 출력 예시를 저장소에 넣는다)을 배포하는 테스트만 한다.

## 73일차 (2027-02-05): 최종 성능·보안 점검
- **성능:** 51일차 표를 다시 잰다. 최종 수치(처리량, 유휴·부하 메모리, 바이너리 크기, 시작 시간)를 README에 넣는다.
- **장시간 실행:** 우분투에서 4시간 혼합 부하를 돌린다(동시 8, 작업당 8 GiB 한도). 메모리 누수, 파일 디스크립터 증가, 남은 컨테이너와 프로세스를 확인한다.
- **보안 2차(44일차 표 갱신):** 45~72일차에 새로 생긴 표면을 점검한다.
  - Pipes 역할 판정
  - SES 수신 엔드포인트
  - ECS 볼륨·비밀
  - Data API
  - AXFR 루프백
  - TLS 키 파일 권한
- 발견한 문제는 그날 고친다.

## 74일차 (2027-02-06): 1.0 문서
- **README:** 서비스별 지원 표(70일차 커버리지 수치), 의도적으로 하지 않는 것, 설치(Homebrew, Docker, 바이너리), 설정 변수 전체 목록, 보안 기본값 설명을 넣는다.
- **`CHANGELOG.md`:** v0.1.0~v1.0.0 요약을 git 태그와 이 문서 결과 표시로 만든다.
- **호환성 약속:**
  - 1.x에서는 관리 엔드포인트 경로, 설정 변수 이름, 스냅샷·SQLite 형식을 깨지 않는다.
  - 깨야 하면 옮겨 주는 코드를 넣는다.
  - 이 약속을 AGENTS.md 5절에 규칙으로 추가한다.
- **마을과 GUI:** 연대기 섬에 1.0 기념 오벨리스크를 넣고, 숫자를 최종값으로 고친다. Playwright로 점검한다.
- `local-cloud-emulator-plan.md`에 최종 상태 절을 넣는다.

## 75일차 (2027-02-07): v1.0.0 릴리스 + 유지보수 모드 전환 (마지막 날)
- 우분투 최종 전체 검증을 돌린다(두 모드, JS·Rust, `ubuntu_verify.sh`, `op_coverage.py`, 컨테이너·이미지·프로세스 0개).
- **v1.0.0을 준비한다.** **태그는 사용자 승인 후에만 푸시한다.**
  - Homebrew sha256을 반영하고, 리눅스 바이너리로 확인한다.
  - 맥 바이너리를 실행할 수 없었으면 그렇다고 적는다.
- **최종 회고:** 이 문서 끝에 적는다.
  - 75일 결과 표(완료, 일부, 못 함)
  - 승인 대기로 대안 처리한 항목
  - 끝내 테스트하지 않은 경로
  - 실기기 점검 여부
- **유지보수 모드 규칙을 AGENTS.md 7절에 쓰고 7절을 이것으로 바꾼다.**
  - 새 기능은 사용자 요청이 있을 때만 한다.
  - 버그는 재현 테스트를 먼저 넣고 고친다.
  - boto3, JS, Rust SDK 새 버전이 나오면 한 달에 한 번 스위트를 돌려 깨진 것만 고친다(CI는 매주 실행으로 바꿔도 되는지 묻는다).
  - 보안 문제가 생기면 즉시 패치 릴리스를 낸다(승인 후).
- 이 문서 머리에 "**계획 종료(2027-02-07). 이후는 AGENTS.md 7절 유지보수 규칙을 따른다.**"를 적는다. 문서는 기록으로 남기고 지우지 않는다.
- 우분투를 끈다.

---

## 끝낼 때 보고 형식 (매일)
- 이 문서의 그날 제목 옆에 결과 표시와 커밋 해시를 단다.
- 한 일과 CI 결과
- 테스트한 것과 **테스트하지 않은 것**을 구분해 적는다.
- 우분투 상태: 프로세스 0개, 컨테이너 0개, 전원 끔
- 다음 날 할 일과 막힌 점(사용자 결정이 필요한 것). 릴리스 태그 승인은 릴리스 날(1·13·23·35·44·53·62·75일차)에 꼭 묻는다. 새 크레이트 승인은 53일차에, 도구 설치 승인은 72일차에 묻는다.
