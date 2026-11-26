# rocalcloud 작업 계획서 (2026-11-25 ~ 2026-12-17, 23일)

이 문서는 일을 넘겨받는 작업자(모델)를 위한 날짜별 계획서다. **먼저 `AGENTS.md` 전체를 읽는다.** 구조, 요청 흐름, 서비스 추가 패턴은 거기 있다.
이 문서와 AGENTS.md가 충돌하면 AGENTS.md가 맞다.

**이 문서는 지우지 않는다. 계속 이어 쓰는 계획서다.**
- 하루가 끝나면 그날 제목 옆에 `✅ 완료`, `⚠️ 일부`, `❌ 못 함` 중 하나와 커밋 해시를 적는다.
- 못 끝낸 일은 다음 날 맨 앞으로 옮긴다. 다른 날 항목을 건너뛰어 먼저 하지 않는다.
- 마지막 날(지금은 23일차)에는 그다음 10일 계획을 이 문서 끝에 이어 쓴다.

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

## 17일차 (2026-12-11): RDS 스냅샷·파라미터 그룹 (Docker 필요)
- **`managed.rs` 3행:**
  - 스냅샷: `CreateDBSnapshot`, `DescribeDBSnapshots`, `DeleteDBSnapshot`, `RestoreDBInstanceFromDBSnapshot`
  - 구현은 `docker commit`이 가장 짧다. 이미지 크기를 보고에 적는다. 스냅샷 이미지는 `rocalcloud-snap-` 접두사로 만들고, 리셋·삭제할 때 지운다.
- **파라미터 그룹:** `CreateDBParameterGroup`, `ModifyDBParameterGroup`, `DescribeDBParameters`
  - 적용은 컨테이너 재시작할 때 `-c key=value`(Postgres) 또는 `--key=value`(MySQL)로 한다. 모르는 파라미터는 거부한다.
- 테스트:
  - 테이블에 행을 넣고 스냅샷을 찍은 뒤 복원한 인스턴스에서 그 행이 보여야 한다.
  - `max_connections` 파라미터가 `SHOW`로 확인되어야 한다.
  - 끝나면 남은 컨테이너와 스냅샷 이미지가 0개여야 한다.

## 18일차 (2026-12-12): Route53 헬스 체크·DNS TCP
- **`route53.rs` 4행:** `CreateHealthCheck`, `GetHealthCheck`, `ListHealthChecks`, `DeleteHealthCheck`, `GetHealthCheckStatus`
  - 종류는 TCP와 HTTP이고, **대상은 루프백만 허용한다**(SSRF 방지). 주기는 10초 이상이다.
- 페일오버와 가중치 레코드의 `HealthCheckId`를 반영한다. PRIMARY가 unhealthy면 SECONDARY로 답한다.
- **DNS over TCP:** 기존 UDP 응답 코드를 다시 써서 같은 포트 TCP로도 받는다(2바이트 길이 접두사). 512바이트를 넘는 응답은 UDP에서 TC 비트를 세운다.
- 테스트:
  - 테스트 안에서 루프백 서버를 띄웠다 내리면 페일오버 응답이 바뀌어야 한다.
  - `dnspython` TCP 질의가 되어야 한다.
  - 외부 주소 헬스 체크는 생성할 때 거부되어야 한다.

## 19일차 (2026-12-13): DynamoDB 트랜잭션·스트림·숫자 점검
- **점검 위주로 한다.** 아래를 테스트로 확인하고, 틀린 것만 고친다.
  - `TransactWriteItems`: 실패할 때 `CancellationReasons` 순서와 코드, `ClientRequestToken` 10분 멱등성, 같은 항목 두 번 지정 거부
  - `TransactGetItems`
  - Streams: `StreamViewType` 4종의 레코드 모양. Lambda 매핑의 `FilterCriteria`가 있으면 그것도 본다.
- **`ddb.rs` 11행:** 키가 아닌 N 값과 `ADD`/`SET a = a + :n` 산술도 십진 문자열로 계산해 정밀도를 지킨다. 3일차의 비교 코드를 다시 쓴다. 38자리를 넘으면 `ValidationException`으로 답한다.
- 테스트:
  - `9007199254740993` + 1이 정확해야 한다.
  - 트랜잭션 조건이 실패하면 `CancellationReasons`에 `ConditionalCheckFailed`가 제 위치에 있어야 한다.
  - 같은 토큰으로 다시 보내면 한 번만 적용되어야 한다.

## 20일차 (2026-12-14): API Gateway REST v1 (1/2) — 리소스·메서드·배포
- **`apigw.rs` 4행:** REST API(`apigateway` 서비스, REST-JSON 프로토콜)를 시작한다.
  - 연산: `CreateRestApi`, `GetResources`, `CreateResource`, `PutMethod`, `PutIntegration`(AWS_PROXY Lambda, MOCK), `PutMethodResponse`, `PutIntegrationResponse`, `CreateDeployment`, `CreateStage`, `Get*`, `Delete*`
- 호출 경로는 `/_restapi/{id}/{stage}/...`이다. HTTP API의 `/_api/`와 같은 처리 방식을 다시 쓴다.
- **REST v1에서는 배포가 실제로 스냅샷을 만든다.** 배포 전 변경은 호출에 보이지 않아야 한다. HTTP API의 "배포는 no-op"과 다른 점을 주석에 적는다.
- 매핑 템플릿(VTL)은 하지 않는다. AWS 통합과 `requestTemplates`는 거부한다.
- 테스트:
  - Lambda 프록시 호출이 200이어야 하고, 이벤트 모양이 REST v1 형식(`resource`, `httpMethod`, `requestContext.stage`)이어야 한다.
  - MOCK은 고정 응답을 돌려주어야 한다.
  - 배포 전 변경은 반영되지 않아야 한다.

## 21일차 (2026-12-15): API Gateway REST v1 (2/2) — 인가자·API 키·CFN
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

## 22일차 (2026-12-16): S3 체크섬·트레일러 체크섬 재계산
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

## 23일차 (2026-12-17): v0.1.7 릴리스 + 다음 10일 계획
- 우분투 전체 검증을 돌린다(두 모드, JS·Rust 스위트, `ubuntu_verify.sh`, 컨테이너 0개, 스냅샷 이미지 0개).
- v0.1.7을 준비한다. 절차는 1일차 1-2와 같다.
  - **태그 푸시는 사용자 승인을 받은 뒤에만 한다.**
  - 아직 승인을 기다리는 태그(v0.1.5, v0.1.6)가 남아 있으면, 순서대로 낼지 하나로 묶을지 사용자에게 묻는다.
- AGENTS.md 1·7·8절을 갱신하고, `town.html` 12절 숫자를 고친다. Playwright 화면 점검도 한다.
- **이 문서 끝에 24~33일차(10일) 계획을 이어 쓴다.** 남은 `ponytail:` 주석과 7절 후보에서 고른다.
  - 후보: Lambda 레이어·웜 컨테이너, Cognito SRP·MFA(이틀), CFN 중첩 스택·SAM 변환(이틀), Kinesis enhanced fan-out, EC2 NACL·피어링, ALB TLS·스티키 세션, SNS http 엔드포인트(루프백만), Step Functions Express 동기 실행

---

## 끝낼 때 보고 형식 (매일)
- 이 문서의 그날 제목 옆에 결과 표시와 커밋 해시를 단다.
- 한 일과 CI 결과
- 테스트한 것과 **테스트하지 않은 것**을 구분해 적는다.
- 우분투 상태: 프로세스 0개, 컨테이너 0개, 전원 끔
- 다음 날 할 일과 막힌 점(사용자 결정이 필요한 것). 릴리스 태그 승인은 1일차·13일차·23일차에 꼭 묻는다.
