# rocalcloud — 인수인계 지침 (2026-11-25)

다음 작업자(모델)가 바로 이어서 코딩할 수 있도록 현재 상태, 규칙, 남은 일을 정리한 문서다.
**작업자는 `HANDOFF.md`(날짜별 작업 계획서, 2026-11-25~2027-02-07, 75일차가 끝, 지우지 않음)를 먼저 본다.** 계획 원본은 `local-cloud-emulator-plan.md`. 이 문서와 충돌하면 계획서가 목표, 이 문서가 현재 사실이다.

## 1. 현재 상태

- 계획서 4장 체크리스트를 실제 상태로 표시했다(2026-11-21). 6장 순서 **1~8단계 전부 완료** (코어·22개 서비스·GUI·캐릭터 마을·해설 에이전트·검증 에이전트·Python/JS/Rust 3개 SDK 호환성 스위트·Dockerfile/Homebrew/GitHub Actions CI·Release 패키징·문서 정비).
- 2026-11-21 추가: S3 버킷 정책·SQS 큐 정책(`Policy` 속성, Put/Get/DeleteBucketPolicy, 같은 계정 규칙: 명시적 Deny 우선, 신원·버킷 정책 중 하나의 Allow면 허용, 계정 지정은 위임일 뿐 사용자 허용 아님, 루트는 정책 관리 항상 가능), SQS 메시지 속성(MD5 검증). 선택적 SigV4 검증, SQS FIFO, DynamoDB 400KB 한도, 검사 시나리오 7개, 설정 파일·설정 화면, SKILL.md.
- 이후 추가: JSON 상태 스냅샷, 3D(Three.js) 캐릭터 마을(본섬 28개 시설 + 다리 건너 다운타운 + 모노레일 건너 "연대기 섬": 계획서 0~10단계 오벨리스크와 SigV4·FIFO·400KB·SDK 경기장·릴리스·Homebrew·Docker·우분투·검사관 훈련장·Pages 포털·/_ui 전광판, `town.html` 12절), GitHub Pages 마을(`pages.yml`). Pages 마을은 방문자 PC의 로컬 에뮬레이터
  (`127.0.0.1:4566`, `?api=`)에 SSE로 붙어 실제 트래픽을 보여 주고, 연결 전에는 목업 트래픽을 돌린다. Pages에서는 자동 연결·재시도를 하지 않고 🔌 연결 버튼을 눌렀을 때만 붙는다(실패한 연결마다 브라우저가 ERR_CONNECTION_REFUSED를 콘솔에 남기기 때문). `/_town`(같은 출처)은 자동 연결.
- 2026-11-23 추가: IAM 조건 연산자 확장 — Numeric*·Date*·IpAddress/NotIpAddress(IPv4·IPv6 CIDR), ForAnyValue/ForAllValues 한정자, 요청 컨텍스트에 `aws:SourceIp`·`aws:EpochTime`·`aws:CurrentTime` 추가. boto3 테스트 31개.
- 2026-11-23 추가2: `STRICT_DELIVERY=1`(ENFORCE_IAM 함께) — 대상 리소스 정책이 없으면 SNS·EventBridge·S3 배달을 AWS처럼 거부. 기본은 관대(정책 없음 허용). boto3 테스트 32개(둘째 에뮬레이터 4567 포트로 확인).
- 2026-11-23 추가3: SNS 필터 정책에 `numeric`(단일 비교·두 쌍 범위)·`suffix` 추가, 단위 테스트 `filter_policy_operators` 추가.
- 2026-11-23 추가4: SigV4 시계 오차 검증 — 헤더 서명의 `x-amz-date`가 15분 이상 어긋나면 `RequestTimeTooSkewed`(사전 서명 URL은 `X-Amz-Expires` 규칙만 적용, 단위 테스트 `clock_skew_rejects_stale_header_dates`).
- 2026-11-23 추가5: STS 세션 키 만료 — `AssumeRole` 발급 키가 `Expiration` 지나면 `ExpiredToken`(기본·VERIFY 모드 모두, 스냅샷에도 저장). Lambda 실행용 내부 세션은 호출마다 새로 발급하므로 만료 없음. `DurationSeconds` 범위 검사는 하지 않음(AWS는 900~43200).
- 2026-11-23 추가6: Kinesis 리샤딩 — `SplitShard`(ShardToSplit)·`MergeShards`. 샤드 모델을 명시적(범위·닫힘)로 개편, 닫힌 샤드는 읽기 유지·새 레코드는 열린 샤드로만 배치, Lambda 매핑은 새 샤드 자동 추적(끝에만 추가해 인덱스 안정).
- 2026-11-23 추가7: S3 알림 대상 저장 시 검증 — 큐·토픽·함수 ARN이 실제로 존재해야 `PutBucketNotificationConfiguration` 성공(없으면 400 `InvalidArgument`).
- 2026-11-23 추가8: Route53 라우팅 정책 — 가중치(무작위, 0은 당첨 안 됨)·페일오버(PRIMARY 우선)·지연시간(첫 세트; 클라이언트 리전을 모름). 레코드 세트 정체성이 (이름·타입·SetIdentifier)로 확장, List에 정책 속성 표시.
- 2026-11-23 추가9: CloudWatch Logs 필터 패턴(`?OR` 리스트, JSON `{ $.a.b = "x" $.n != 2 }`, `*` 존재 체크) + 미검증 경계 경로 테스트(`test_handoff_edge_paths`: Kinesis→Lambda 재시도·건너뛰기, SNS/EB→Lambda 별칭 버전, S3/EB→SQS 큐 정책 Deny, `cron_next` 월말·윤년·요일·과거연도 단위 테스트). boto3 테스트 33개.
- 2026-11-24 추가10: Lambda 비동기 호출 대상(Destinations) — `Put/Get/Update/DeleteFunctionEventInvokeConfig`(2019-09-25 경로, POST 직렬화), 실패 재시도(최대 2, 고정 200ms 백오프)·이벤트 수명 뒤 `RetriesExhausted`/`EventAgeExceeded`·AWS 형식 결과 봉투로 SQS·SNS·Lambda·EventBridge 버스 배달(대상은 저장 시 검증). Kinesis 매핑 `BisectBatchOnFunctionError`(부분 성공 보존)·`DestinationConfig.OnFailure`(건너뛴 배치 메타데이터 SQS/SNS 배달). 배달은 `send_to_target` 재사용(버스 분기 추가), `service_gate`은 lambda 발신자를 판정하지 않음(실행 역할 시맨틱). boto3 테스트 34개.
- 2026-11-24 추가11: DynamoDB 숫자 키 정밀도 — N 키를 원본 십진 문자열 그대로 저장·비교(부호 → 정수 자릿수 → 자릿 순서, 지수 정규화 `1e3`=`1000`), 38자리 초과 키는 `ValidationException`. 정렬 키·`KeyConditionExpression`의 `<`·`BETWEEN`·조건 비교(`cmp_av`)도 같은 비교 사용. 프로젝션 `a[0].x, a[0].y`가 한 원소로 병합. 단위 테스트 35개.
- 2026-11-24 추가12: SQS 메시지별 `DelaySeconds`(표준 큐 0~900초, 음수/초과/FIFO 거부, 표준 큐 FIFO 파라미터 거부) + SNS FIFO 토픽(`.fifo`+`FifoTopic=true`, `MessageGroupId` 필수, 5분 중복 제거/`ContentBasedDeduplication`, FIFO SQS 구독만 허용, 삭제·스냅샷 복원 시 dedup 캐시 정리). `main.rs` `check_sns_subscribe`·`sqs.rs` `parse_delay_seconds` 리팩토링. 단위 테스트 37개, boto3 테스트 35개.
- 2026-11-24 추가13: Step Functions JSONPath 확장(`[*]`, `[-1]`, `['key']`, `$$.Execution.Id`/`$$.State.Name`/`$$.Map.Item.Value`·Map 내부 컨텍스트 전파, `?()` 필터식 거부) + 내장 함수 12종(`ArrayPartition`/`Contains`/`Range`/`GetItem`/`Length`/`Unique`, `Base64Encode`/`Decode`, `Hash`(MD5/SHA-256/384/512), `StringSplit`, `JsonMerge`, `MathRandom`). 단위 테스트 39개, boto3 테스트 36개.
- 2026-11-24 추가14: EventBridge 대상별 `RetryPolicy`·`DeadLetterConfig`(SQS DLQ, `RULE_ARN`/`TARGET_ARN`/`ERROR_CODE`/`ERROR_MESSAGE` 속성) + 아카이브(`Create/Describe/List/DeleteArchive`, 스냅샷 저장)·재생(`Start/Describe/ListReplay`, `replay-name` 부착), API destinations 거부. 단위 테스트 40개, boto3 테스트 37개.
- 2026-11-24 추가15: API Gateway HTTP API 인가자(`Create/Get/Update/DeleteAuthorizer`, 라우트 `UpdateRoute`·`AuthorizationType`/`AuthorizerId`) — JWT 인가자(로컬 Cognito 풀 RS256·`iss`/`aud`/`client_id` 검증, 외부 issuer 거부) + Lambda `REQUEST` 인가자(payload 2.0 simple response `{isAuthorized, context}` → `requestContext.authorizer.lambda`), 토큰 없음 401·검증 실패 403. 단위 테스트 42개, boto3 테스트 38개.
- 2026-11-25 추가16: API Gateway CORS·HTTP_PROXY·스테이지 변수 — `CorsConfiguration`(lowerCamel 와이어, allowOrigins·Methods·Headers·MaxAge·Credentials, `*`+Credentials 조합 거부): OPTIONS 사전 요청은 라우트 없이도 허용된 출처면 204+헤더, 실제 응답에도 CORS 헤더. `HTTP_PROXY` 통합은 저장 시 루프백(http://127.0.0.1·localhost) 검증(SSRF 차단, `${stageVariables.x}` 자리표시자는 치환 후 재검사), 메서드·경로·쿼리·헤더 전달(홉바이홉 헤더 제외, 5초 타임아웃, 연결 닫힘까지 읽기). 스테이지 변수(Create/UpdateStage·GetStage)로 통합 URI 치환. `PATCH/PUT /apis/{id}`(UpdateApi: name·cors). 단위 테스트 44개, boto3 테스트 39개.
- 2026-11-25 추가17: Cognito 그룹·Lambda 트리거 — 그룹(`Create/Get/List/DeleteGroup` + `AdminAdd/Remove/ListGroupsForUser`, `GroupExistsException`·중복 가입 방지)으로 토큰 ID·액세스 모두 `cognito:groups` 클레임. `LambdaConfig` 트리거 3종: `PreSignUp`(함수 실패 → `UserLambdaValidationException`, `autoConfirmUser`·`autoVerifyEmail` 반영, 가입 전 실행), `PostConfirmation`(확정 후 최선 실행), `PreTokenGeneration`(`claimsToAddOrOverride`·`claimsToSuppress`를 ID 토큰에 반영해 재서명, 이벤트는 AWS 형식 `{version, triggerSource, userPoolId, userName, request, response}`). 트리거 실행은 main.rs가 오케스트레이션(cognito는 이벤트 생성만). 단위 테스트 45개, boto3 테스트 40개.
- 2026-11-25 추가18: Kinesis 보존 기간·`UpdateShardCount` — `RetentionPeriodHours`(기본 24, `Increase/DecreaseStreamRetentionPeriod` 24..8760 범위·방향 검증, boto3 와이어의 `RetentionPeriodHours` 키도 수용), 만료 레코드는 `GetRecords`·TRIM_HORIZON·람다 폴링에서 숨김(주입 시계로 단위 테스트, 저장은 유지). `UpdateShardCount`(UNIFORM_SCALING, 1..64, 대상 수 ≠ 현재 열린 샤드 수): 열린 샤드 전부 닫고 균등 분할로 재생성, 기존 레코드는 닫힌 샤드에 그대로. S3 ListObjectsV2 경계 점검(키 1000개·MaxKeys 7·delimiter 이어받기 — 코드 수정 불필요, 테스트만 추가). 단위 테스트 47개, boto3 테스트 42개.
- 2026-11-25 추가19: CloudFormation 제자리 업데이트·Export — 속성 변화가 타입별 in-place 목록(SQS 큐 속성·Lambda 환경/메모리/타임아웃/설명·SNS DisplayName·DDB 처리량, `UpdateTable` 신규)에 있으면 같은 물리 ID로 업데이트(이벤트 UPDATE_IN_PROGRESS/COMPLETE), 아니면 기존처럼 교체. `Outputs.Export.Name` → `ListExports`(이름 정렬)·`ListImports`·`Fn::ImportValue`(배포된 스택의 export에서 해석), import하는 스택이 있으면 export 스택 삭제·값 변경 거부. 단위 테스트 48개, boto3 테스트 43개.
- 2026-11-26 추가20: Step Functions 작업 토큰·타임아웃 — `.waitForTaskToken` 통합(`$$$.Task.Token` 컨텍스트 주입, 파라미터의 `DataType/StringValue` 속성으로 토큰 전달), `SendTaskSuccess/Failure/Heartbeat`(모르는 토큰 `TaskDoesNotExist`, 소진 토큰 `TaskTimedOut`, 하트비트 없는 작업에 하트비트 `TaskTimedOut`), Task `TimeoutSeconds`(일반 작업 기본 60초·`States.Timeout`→Retry/Catch)·`HeartbeatSeconds`, `StopExecution`이 대기 중 토큰을 중단. 대기 토큰은 메모리만(재시작 유실, ponytail). 단위 테스트 49개, boto3 테스트 44개.
- 2026-11-26 추가21: Lambda 가중치 별칭·한정자별 호출 설정 — 별칭 `RoutingConfig.AdditionalVersionWeights`(1개 버전, 가중치 0 초과 1 이하, 별칭 버전과 달라야 함, 2개 이상·범위 밖·같은 버전은 `InvalidParameterValueException`), 호출 시 `rand`로 버 선택·`ExecutedVersion`에 실제 버전, EventInvokeConfig를 한정자(`$LATEST`·버전 스냅션·별칭)별 저장(별칭 미설정 시 `$LATEST` 상속), `Get/Put/Update/DeleteFunctionEventInvokeConfig`가 `?Qualifier=`를 따름. 단위 테스트 49개, boto3 테스트 45개.
- 2026-11-26 추가22: ECS 롤링 배포·헬스 체크 — 서비스 업데이트 시 `deploymentConfiguration`(minimumHealthyPercent·maximumPercent, 기본 100/200)에 따라 새 정의 태스크를 surge로 띄우고 오래된 태스크를 최소 건강 수 아래로 안 내려가게 교체(`deployments`에 PRIMARY·ACTIVE, `rolloutState` IN_PROGRESS/COMPLETED), 컨테이너 `healthCheck.command`를 docker `--health-cmd`(2초 간격·3회 재시도)로 전달하고 unhealthy 태스크는 교체(사유 `Task failed container health checks`). 단위 테스트 49개, boto3 테스트 46개.
- 2026-11-26 추가23: RDS 스냅샷·파라미터 그룹 — `Create/Describe/DeleteDBSnapshot`·`RestoreDBInstanceFromDBSnapshot`(docker commit, 데이터는 볼륨 아닌 컨테이너 레이어에: postgres `PGDATA=/pgdata`, mysql `--datadir=/var/lib/mysql-local`; 기본 이미지 크기 postgres:16-alpine 420MB·mysql:8.4 1.12GB 참고), `Create/Modify/Describe/DeleteDBParameterGroup`(허용 파라미터 화이트리스트 8종, 알 수 없는 이름 거부, 사용 중 그룹 삭제 거부) — 값은 컨테이너 (재)생성 시 적용, `RebootDBInstance`는 컨테이너 재생성. 단위 테스트 49개, boto3 테스트 47개.
- 2026-11-26 추가24: Route53 헬스 체크·DNS over TCP — `Create/Get/List/DeleteHealthCheck`·`GetHealthCheckStatus`(TCP·HTTP, 루프백 전용 SSRF 차단, `RequestInterval>=10`, HTTP `ResourcePath` 반영, 사용 중 삭제 거부·미존재 `NoSuchHealthCheck`), 페일오버/가중치 레코드 `HealthCheckId` 게이트, DNS TCP(같은 포트 2바이트 길이 접두사) 및 UDP >512B `TC` 비트 절단. 단위 테스트 50개, boto3 테스트 48개.
- 2026-11-26 추가25(19일차): DDB 트랜잭션·스트림·숫자 — `TransactWriteItems`에 같은 항목 두 번 거부·`ClientRequestToken` 10분 멱등성(같은 토큰 다른 파라미터는 `ValidationException`), `ADD`/`SET a = a + :n`을 정확한 십진 문자열 연산으로 교체(키가 아닌 N값·NS·중첩 M/L도 38자리 검사), DynamoDB Streams(테이블 `StreamSpecification` 4종 `StreamViewType`, `ListStreams`/`DescribeStream`/`GetShardIterator`(LATEST·TRIM_HORIZON·AT/AFTER_SEQUENCE_NUMBER)/`GetRecords`, 반복자는 "테이블|인덱스" 문자열 — ponytail: 불투명 아님·보존 기간 없음, 시퀀스는 21자리, shardId는 35자리(boto3 최소 길이 28)). boto3가 `eventSourceARN`(Record 모델에 없음)·ListStreams의 `StreamStatus`를 drop함. 단위 테스트 51개, boto3 테스트 49개.
- 2026-11-27 추가26(20일차): API Gateway REST v1 — `/restapis` 컨트롤 플레인(CreateRestApi·GetResources·CreateResource(부모 id가 **경로**에 있음: POST /restapis/{api}/resources/{parent})·PutMethod·PutIntegration·Put/Method/IntegrationResponse·CreateDeployment·CreateStage·Get*/Delete*), 호출은 `/_restapi/{apiId}/{stage}/path` — 라우팅 없으면 v1 특유의 403 `Missing Authentication Token`. **배포는 실제 스냅샷**(스테이지는 배포 시점 리소스 트리를 서빙, 배포 후 편집은 재배포 전까지 안 보임 — HTTP API의 no-op 배포와 다름, 주석 참조). AWS_PROXY는 v1 이벤트 모양(`resource`·`httpMethod`·`requestContext.stage`·`pathParameters`), MOCK은 고정 200 빈 몸통. AWS·HTTP 통합과 requestTemplates(VTL)는 BadRequest로 거부. botocore 함정: REST-JSON 파서가 shape 직렬화 `name`을 따라감 — GetResources/GetDeployments 응답 키는 `items`가 아니라 `item`(GetStages도 `item`), `methodResponses`/`integrationResponses`는 리스트 아닌 맵. 단위 테스트 51개, boto3 테스트 50개.
- 2026-11-27 추가27(21일차): REST v1 인가자·API 키·CFN — `CreateAuthorizer`(`COGNITO_USER_POOLS`는 로컬 풀 JWT·`TOKEN`/`REQUEST`는 람다가 돌려준 IAM 정책 문서 해석: 명시적 Deny 우선·`Resource` 글롭 `*`, 401/403 구분), `PutMethod`의 `authorizerId`·`apiKeyRequired`, `CreateApiKey`·`CreateUsagePlan`·`CreateUsagePlanKey`(`x-api-key` 없으면 403 Missing Authentication Token·모르는 키 403 Forbidden·토큰 버킷 초과 429 Too Many Requests — 쿼터는 미구현 ponytail), CFN `AWS::ApiGateway::RestApi/Resource/Method/Deployment/Stage`(Deployment는 Method에 DependsOn 필요 — 스냅샷이 생성 순서를 따르므로). 단위 테스트 51개, boto3 테스트 51개.
- 2026-11-27 추가28(22일차): S3 체크섬·트레일러 재계산 — CRC32·CRC32C는 표 기반 직접 구현, SHA-1은 크레이트 없이 손으로 구현(주석에 선택 기록), SHA-256은 sha2. `x-amz-checksum-*` 헤더는 PutObject에서 검증(불일치 `BadDigest`)·저장, `x-amz-sdk-checksum-algorithm`·`x-amz-checksum-algorithm`은 재계산해 저장. HeadObject는 항상, GetObject는 `x-amz-checksum-mode: ENABLED`(헤더임, 쿼리 아님!)일 때 반환하되 206 Range 응답은 제외(전체 객체 체크섬이므로), `GetObjectAttributes`(`?attributes`+`x-amz-object-attributes`)로 ETag·Checksum·ObjectSize. VERIFY_SIGV4에서 트레일러 `x-amz-checksum-*` 값을 디코딩된 청크 합계로 재계산해 비교(불일치 `BadDigest`). 함정: 변조 헤더는 서명 대상이라 VERIFY 모드에선 서명 검증이 먼저 발화, 이 botocore는 기본(`when_supported`)으로 GetObject마다 checksum-mode 헤더를 붙이고 응답 체크섬을 검증함. 단위 테스트 51개, boto3 테스트 52개.
- 2026-11-28 추가29(26일차): Lambda 웜 실행 — 함수·버전·수정 시각별 상주 프로세스(부트스트랩은 stdin에 요청 JSON 한 줄, fd 1에 결과 JSON 한 줄, 함수 로그는 결과의 `logs` 배열에 담아 경합 없이 수집; stderr은 /dev/null). 콜드 스타트 헤더 `x-rc-cold-start`·REPORT의 `Init Duration`은 첫 호출에만, 유휴 5분(`lambda::sweep_warm`, 30초 리퍼가 main.rs에서 구동) 뒤 종료, 설정·코드 변경은 키에 modified를 넣어 교체, 동시 호출은 유휴 풀에서 꺼내 쓰고 없으면 새로 뜸(SLOTS=8 유지), `exit()`·타임아웃은 프로세스 폐기. `pgrep -f rocalcloud-lambda-warm`으로 잔여 프로세스 확인. 함정: `print("a", x)`는 write 호출마다 쪼개져 들어오므로 부트스트랩은 버퍼에서 개행 기준으로만 줄을 나눠야 함; 셧다운 시 kill_on_drop으로 잔여 0. 단위 테스트 52개, boto3 테스트 54개.
- 2026-11-28 추가30(27일차): Lambda 컨테이너 이미지 — `PackageType=Image`+`Code.ImageUri`(로컬 docker에 있는 이미지만, `docker image inspect` 검증, 없으면 InvalidParameterValueException; ECR 흉내·pull 없음). 실행은 `docker run -d --rm -p 127.0.0.1:{free}:8080 --memory {MemorySize}m --add-host host.docker.internal:host-gateway` 후 `POST /2015-03-31/functions/function/invocations`(자체 최소 HTTP 클라이언트, 청크 디코딩 포함, RIE 부팅 재시도), 로그는 `docker logs` 증분. 풀·유휴 5분·forget(삭제·코드/설정 변경)·`x-rc-cold-start`·Init Duration은 26일차와 같은 규칙. 함정: docker CLI에서 `-e` 등 옵션은 반드시 이미지 이름 **앞**에(뒤에 붙으면 컨테이너 인자가 되어 엔트리포인트 exit 142); 공식 베이스 이미지의 RIE는 핸들러를 CMD로 받음; App이 셧다운 때 드롭되지 않을 수 있어 main 끝에서 img 풀을 명시적으로 비움(Drop이 docker rm -f). 함수 오류는 RIE의 `Lambda-Runtime-Function-Error-Type` 헤더로 구분. 단위 테스트 52개, boto3 테스트 55개.
- 2026-11-27 추가29(25일차): Lambda 레이어 — `PublishLayerVersion`(zip, `/2018-10-31/layers` 경로)·`GetLayerVersion`·`GetLayerVersionByArn`(`?find=LayerVersion`)·`ListLayers`·`ListLayerVersions`(최신 먼저, `CompatibleRuntime` 필터)·`DeleteLayerVersion`(멱등, 번호 재사용 안 함, 이미 쓰는 함수는 계속 동작)·`Add/Get/RemoveLayerVersionPermission`(이 계정 또는 `*`만). 함수 `Layers`(최대 5개, 레이어당 한 버전)는 실행 시 뒤 레이어가 먼저 오도록 `PYTHONPATH`(`python/`·`python/lib/<runtime>/site-packages`)·`NODE_PATH`(`nodejs/node_modules`, require만)로 연결. 경로 탈출 zip은 거부. 단위 테스트 52개, boto3 테스트 53개.
- 2026-11-25 추가20: 검증 에이전트 시나리오 6개 추가(21→27: 보안 4종 `sec-clock-skew`·`sec-sts-expired`·`sec-strict-delivery`·`sec-jwt-bypass`, 사고 2종 `inc-lambda-dest`·`inc-events-dlq`, `poll_sqs_body`·`xml_tag` 리팩토링), JS v3(5→8)·Rust SDK(4→7) 스위트 확장(FIFO·고정밀 숫자 키·중첩 경로·IAM 조건/버킷 정책·S3 페이지네이션), 연대기 섬 숫자 동기화.
- `v0.1.0` 릴리스 완료(2026-11-21): 바이너리 3종 + SHA256SUMS, Homebrew sha256 반영.
- `v0.1.7` 릴리스 준비(2026-11-27, 23일차): 14~22일차 기능 포함 — Step Functions 작업 토큰·타임아웃, Lambda 가중치 별칭·한정자별 호출 설정, ECS 롤링 배포·헬스 체크, RDS 스냅샷·파라미터 그룹, Route53 헬스 체크·DNS TCP, DDB 정확 십진 산술·트랜잭션 멱등성·스트림, API Gateway REST v1(리소스·배포 스냅샷·인가자·API 키·CFN), S3 체크섬·트레일러 재계산. 태그 푸시(v0.1.5/v0.1.6/v0.1.7 정리 포함)는 사용자 승인 대기.
- `v0.1.6` 릴리스 준비(2026-11-26, 13일차): 8~12일차 기능 포함 — API Gateway CORS·HTTP_PROXY(루프백)·스테이지 변수·PATCH/PUT UpdateApi, Cognito 그룹·Lambda 트리거(PreSignUp/PostConfirmation/PreTokenGeneration), Kinesis 보존기간·UpdateShardCount, S3 목록 경계, CloudFormation 제자리 업데이트·Export/ImportValue, 검사관 시나리오 27개, JS(8)·Rust(7) SDK 스위트 확장. Pages 배포 재시도 스텝 추가. 태그 푸시는 사용자 승인 대기.
- `v0.1.5` 릴리스(2026-11-25): EventBridge `cron()`·InputTransformer, Kinesis→Lambda 매핑, DynamoDB 중첩 경로, Lambda 버전·별칭, IAM 조건 연산자(Numeric·Date·IpAddress·한정자), `STRICT_DELIVERY=1`, SNS 필터 numeric·suffix, SigV4 시계 오차, STS 만료, Kinesis 리샤딩, S3 알림 대상 검증, Route53 라우팅 정책, Logs 필터 패턴. 우분투 전체 검증(스위트 두 모드) 통과 뒤 태그. Homebrew는 태그 뒤 반영.
- `v0.1.4` 릴리스(2026-11-22): ALB 요청별 규칙 라우팅, aws-chunked 트레일러 서명 검증, SNS·EventBridge·S3 배달의 대상 정책 판정(서비스 주체). Homebrew 0.1.4.
- `v0.1.3` 릴리스 완료(2026-11-21): SNS·Lambda 리소스 정책, ALB 리스너 규칙, aws-chunked 서명 검증. release.yml도 Node 24 액션으로. Homebrew 0.1.3.
- `v0.1.2` 릴리스 완료(2026-11-21): 버킷·큐 정책, SQS 메시지 속성, Step Functions 동시 실행. Homebrew 0.1.2.
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
tests/sdk_test.py  boto3 호환성 테스트 53개 (주 통합 테스트), tests/js·tests/rust는 JS v3(8개)·Rust SDK(7개) 스위트
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
- 원격 전원 제어(맥 → 우분투): `python3 tools/ubuntu_power.py status | wake --wait | off` (MAC·IP는 git 제외 로컬 파일 `.ubuntu_power.env`에 저장, 우분투 `static-enp4s0`에 `wake-on-lan=magic` 영구 활성화 완료).
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
- 내장 시나리오 27개: 보안 12(버킷 정책 Deny·잠김 방지·시계 오차·STS 만료·배달 정책·JWT 우회 포함), 장애 6(스로틀·5xx·지연·부분 실패·연결 끊김·부하 중 재생성), 사고 6(DLQ·Lambda 반복 실패·큐 폭주·저장소 한도·Lambda Destinations·EventBridge DLQ), 성능 2(동시 처리량·메모리 증가), 퍼징 1. 파괴적 작업은 `rc-insp-` 접두사 리소스에서만.
- 요청은 `local_http()` 하나로 나가며 `resign()`이 진짜 SigV4로 서명한다(`sig_header()`의 `Signature=00`은 자리표시).
  `VERIFY_SIGV4=1`이면 서명 없는 요청도 루트로 서명한다. 서명 없이 보내야 하는 검사는 `x-rc-unsigned` 헤더를 단다.
- 새 시나리오: `sc_x()` 함수 → `run_inner()`의 `plan` 목록과 `match id`에 추가 → `make_result()`로 결과.

## 7. 다음에 할 일 (2026-11-27 기준, 우선순위 순)
최신 태그는 `v0.1.4`, `v0.1.7` 릴리스 준비 완료(v0.1.5·v0.1.6·v0.1.7 태그 푸시는 사용자 승인 대기). HANDOFF.md 1~27일차 완료, 28~75일차 계획이 이어진다. 남은 한계는 각 파일의 `ponytail:` 주석(`grep -rn ponytail core/src`)이 목록이다.

1. **실기기 점검**(사용자 도움 필요): 실제 휴대폰·실제 Safari·GPU가 약한 노트북에서 Pages 마을을 연다.
   연대기 섬 숫자(SDK 테스트 55/8/7개, 시나리오 27개, GPU 65°C)는 `town.html` 12절에 손으로 적은 값이니 바뀌면 같이 고친다.
2. (선택) `?api=`로 IPv6 `[::1]`: CSP가 IPv6 리터럴을 못 받으므로 요청이 있을 때만.
3. (선택) SigV4a: ECDSA P-256 크레이트 추가가 필요하므로 사용자 요청이 있을 때만.
4. 26일차(2026-12-20)부터 HANDOFF.md의 Lambda 레이어·웜 실행·컨테이너 이미지·Cognito MFA 등 계획을 따른다.

각 항목은 sdk_test.py에 정상·오류 경로 테스트를 같이 넣고, 끝나면 마을(`town.html`)·GUI·문서를 같이 갱신한다.
큰 변경 뒤에는 4절 방법으로 우분투 전체 검증을 돌린다.

## 8. 알려진 한계 (요약)
상태는 기본 인메모리(JSON 스냅샷 `RC_STATE_FILE` 또는 SQLite `RC_SQLITE_FILE`로 영속 저장 가능), SigV4 서명은 `VERIFY_SIGV4=1`일 때만 검증(SigV2 거부,
aws-chunked 조각 서명·트레일러 서명·트레일러 체크섬 재계산까지 검증, SigV4a 미지원), 리소스 기반 정책은 S3 버킷·SQS 큐·SNS 토픽·Lambda 함수(AddPermission)를 평가, SNS·EventBridge·S3의 배달도 `ENFORCE_IAM=1`이면 대상 정책을 서비스 주체(`sns.amazonaws.com` 등)와 `aws:SourceArn`으로 판정(대상에 정책이 없으면 기본 허용, `STRICT_DELIVERY=1`이면 AWS처럼 거부), KMS는 진짜 암호 아님,
IAM 조건 연산자는 String·Arn·Bool·Numeric·Date·IpAddress(+IfExists, ForAnyValue/ForAllValues)를 지원하지만 컨텍스트 키가 단일 값이라 다중 값 집합 시맨틱은 없음,
ALB 리스너 규칙(path-pattern·host-header)은 요청마다 고르되 규칙이 있는 리스너는 `Connection: close`로 요청당 연결 하나, Query 프로토콜 구버전 SQS 미지원,
ECS 태스크가 에뮬레이터를 부르려면 `BIND=0.0.0.0:4566` 필요, CloudFormation 교체 대상 자원의 롤백은 미지원(in-place 속성 업데이트·Export 가드는 지원). Lambda EventInvokeConfig는 한정자(`$LATEST`·버전·별칭)별 저장, Kinesis 매핑의 OnFailure 메시지는 배치 메타데이터(레코드 복제 아님). 세부는 각 파일의 `ponytail:` 주석.
