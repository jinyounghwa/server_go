# rocalcloud 3일 작업 인계서 2차 (2026-11-25 ~ 2026-11-27)

이 문서는 잠시 일을 넘겨받는 작업자(모델)를 위한 3일치 계획이다. **먼저 `AGENTS.md` 전체를 읽는다.** 구조, 요청 흐름, 서비스 추가 패턴은 거기 있다.
이 문서와 AGENTS.md가 충돌하면 AGENTS.md가 맞다. 3일이 끝나면 AGENTS.md 7절을 갱신하고 이 문서는 지운다.

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

## 1일차 (2026-11-25): 지난 작업 검증 + v0.1.5 릴리스

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

## 2일차 (2026-11-26): Lambda 실패 처리 (ponytail 목록에서 실사용 빈도가 높은 것)

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

## 3일차 (2026-11-27): DynamoDB 정확도 + 정리

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
- 이 문서(`HANDOFF.md`)는 지우고, AGENTS.md 머리말의 HANDOFF 안내 줄도 지운다.
- 커밋·푸시하고 CI가 초록인지 확인한다. 우분투를 끈다.

### 시간이 남으면 (요청이 없으면 하지 않음)
- IPv6 `?api=[::1]`는 하지 않는다. 사용자가 요청할 때만 한다.
- 실기기 점검(휴대폰, Safari, 약한 노트북)은 사용자에게 제안만 한다.
- API Gateway REST v1, Cognito SRP, CFN 중첩 스택처럼 큰 기능은 시작하지 말고 AGENTS.md 7절 후보로만 적는다.

---

## 끝낼 때 보고 형식 (매일)
- 한 일과 커밋 해시, CI 결과
- 테스트한 것과 **테스트하지 않은 것**을 구분해 적는다.
- 우분투 상태: 프로세스 0개, 컨테이너 0개, 전원 끔
- 다음 날 할 일과 막힌 점(사용자 결정이 필요한 것). 릴리스 태그 승인은 1일차에 꼭 묻는다.
