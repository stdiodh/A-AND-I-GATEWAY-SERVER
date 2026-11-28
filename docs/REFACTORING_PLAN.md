# Gateway 안정적 리팩터링

운영 중인 Gateway와 Discord Monitor Bot을 동작을 바꾸지 않고 정리한 기록입니다. 한 번에 한 종류의 위험만 다루고, 구조를 옮기기 전에 현재 동작을 테스트로 먼저 고정했습니다. 공개 API의 path, method, status, error code는 바꾸지 않았습니다.

## 이전과 현재

| 항목 | 이전 | 현재 |
|---|---|---|
| route와 접근 정책 | route 141개(`application.yaml`)와 method/path 허용 규칙, `SecurityConfig` 접근 규칙이 따로 관리됨 | route 구성과 도달성을 계약 테스트로 고정하고, 접근 규칙은 순서가 있는 전역 catalog 38개를 `SecurityConfig`가 읽음 |
| method/path 허용 규칙 | 필터 안의 allow 254개, deny 13개 목록 | 판정은 부수 효과 없는 `MethodPathPolicyEvaluator`로 분리하고, Auth 73개·Report 16개·Online Judge 20개를 서비스별 catalog로 분리 |
| Monitor Bot 큰 파일 | `interactions.go` 1,542줄, `assignment_ops.go` 1,568줄, `discord_format.go` 1,560줄 | 각각 430줄, 289줄, 701줄 |
| 환경 변수 문서 | `.env.example`과 실제 설정 key를 대조할 수단이 없음 | Gateway 33개와 Monitor Bot 45개의 합집합이 `.env.example` 77개와 같은지 CI가 검사 |
| 배포 설정 | production Compose와 nginx 설정이 workflow 안에 직접 작성됨 | `deploy/` 아래 추적 파일로 분리하고 CD에서 `docker compose config`와 nginx 설정을 검사 |

## 문제

- route를 추가하거나 바꿀 때 허용 규칙과 접근 규칙을 각각 다른 파일에서 맞춰야 했고, 하나를 빠뜨려도 테스트가 알려 주지 않았습니다.
- Monitor Bot의 명령 처리, 과제 진단, Discord 메시지 포맷이 1,500줄이 넘는 파일 세 개에 섞여 있어 명령 하나를 고치려면 파일 전체를 읽어야 했습니다.
- 배포 판정이 Redis 장애를 감지하지 못했고, Monitor Bot은 Discord 설정이 덜 준비된 상태에서도 정상으로 응답할 수 있었습니다.
- 문서의 환경 변수 목록과 실제 설정이 어긋나도 확인할 방법이 없었습니다.

## 바꾼 내용

### 장애와 메모리 위험 차단

- Redis를 배포 때 함께 시작하고, health check에 비밀번호 인증을 쓰며, AOF를 persistent volume에 보존합니다.
- Gateway 배포 판정을 전체 Actuator health로 바꿔 Redis 장애를 감지합니다.
- Monitor Bot의 `/healthz`는 AWS SDK, Discord application ID, 서명 키, interaction handler가 모두 준비된 뒤에만 200을 반환합니다.
- 요청과 응답 원문은 streaming으로 전달하고, 로그에는 64 KiB 이하 body만 남깁니다. auth 요청 body는 한 번만 읽고 최대 크기를 넘으면 413을 반환합니다.
- rate limit은 분 단위로 초기화되는 Count-Min counter를 써서 입력 key 수와 관계없이 메모리 사용량이 고정됩니다.

### route와 보안 정책을 한 곳으로

1. 현재 동작을 먼저 고정했습니다. route 141개(Auth 56, Report 21, Post 44, Online Judge 20)의 구성과 ID 고유성, method가 있는 route 118개가 정책을 통과해 실제로 그 route에 도달하는지 테스트로 확인합니다.
2. 필터의 method/path 판정을 `MethodPathPolicyEvaluator`로 분리하고, 서비스별 허용 규칙을 catalog로 나눴습니다. 전체 254개 규칙의 순서는 fingerprint 테스트로 유지합니다.
3. 접근 규칙은 테스트 코드에서 catalog를 먼저 만들어 실제 Security chain 판정과 같은지 확인한 뒤, production으로 옮겨 `SecurityConfig`가 읽도록 바꿨습니다.

### Monitor Bot 파일 분리

명령 family(dashboard, alert, logs watch, logs query, assignment action, assignment query)마다 handler 계약 테스트를 먼저 추가하고, 그다음 함수만 전용 파일로 옮겼습니다. 과제 진단, 대시보드 포맷, issue 조회와 ack도 같은 방식으로 분리했습니다. 이동하면서 로직은 바꾸지 않았고, 호출처가 없는 handler 6개는 사용처를 전수 검색한 뒤 마지막에 지웠습니다.

### 설정과 문서 맞추기

- production Compose와 nginx 설정을 workflow 밖 추적 파일로 옮겼습니다.
- `.env.example`에 77개 key를 모두 반영하고, `scripts/validate-env-contract.py`로 누락·초과·중복을 CI에서 검사합니다.
- error enum과 `GATEWAY_ERROR_CODES.md`의 code, HTTP status, message가 일치하는지 테스트합니다.
- Jackson 3에서 deprecated된 `asText`, `isTextual`을 같은 의미의 `asString`, `isString`으로 바꿨습니다.

## 확인한 방법

- 매 단계: `./gradlew test bootJar --rerun-tasks --no-daemon`, `cd monitor-bot && go test -race ./... && go vet ./...`
- 정책 전환: 전역 path 105개와 Auth endpoint 73개를 anonymous, USER, ORGANIZER, ADMIN 사용자로 호출해 catalog 판정과 실제 `WebFilterChainProxy` 판정이 같은지 비교했습니다.

  ```bash
  ./gradlew test --tests '*GatewayRoutePolicyContractTests' --tests '*GlobalAccessPolicyCatalogIntegrationTests' --tests '*AuthAccessPolicyProjectionIntegrationTests' --no-daemon
  ```

- 파일 이동: 이동 전후 함수 블록이 byte 단위로 같은지 비교하고, 미리 추가한 계약 테스트가 통과하는지 확인했습니다.
- 환경 변수: `python3 scripts/validate-env-contract.py`를 CI에서 실행합니다.

## 남은 한계

- Post 서비스의 허용 규칙은 아직 서비스별 catalog로 나누지 않았습니다. 경로 rewrite, 역할 인가, public/protected 구분도 각각 별도 변경으로 남아 있습니다.
- Count-Min counter는 hash 충돌로 드물게 제한에 걸리지 않은 요청에 429를 반환할 수 있습니다. 제한을 우회하는 방향의 오차는 없습니다.
- `/v2/auth/me/password`와 `/v1/me/password`, `/v2/me/password`의 접근 등급이 다른 점은 동작을 바꾸지 않기 위해 그대로 두었습니다.
