# Gateway 성능 측정

같은 Mock 서버를 직접 호출할 때와 Gateway를 거쳐 호출할 때를 비교해, Gateway의 정책·라우팅·로깅이 더하는 지연을 쟀습니다. Gateway를 거치면 P95가 8.399ms 늘었고, 인증·권한·요청 제한 오류는 정해진 코드로 응답했습니다.

[README로 돌아가기](../README.md)

## 직접 호출과 Gateway 경유

| 3회 중앙값 | 직접 호출 | Gateway 경유 | 차이 |
| --- | ---: | ---: | ---: |
| P50 | 54.089ms | 59.252ms | 5.163ms |
| P95 | 56.959ms | 65.357ms | 8.399ms |
| P99 | 59.038ms | 67.106ms | - |
| HTTP 실패율 | 0.00% | 0.00% | - |
| check 성공률 | 100.00% | 100.00% | - |

차이는 실행 쌍마다 `Gateway 값 - 직접 호출 값`을 구한 뒤 세 값의 중앙값을 썼습니다. 로컬 회귀 기준이며 운영 처리량이나 성능 개선율이 아닙니다.

![Gateway k6 overhead](./assets/performance/gateway-k6-overhead.svg)

## 오류 응답

| 요청 | 응답 |
| --- | --- |
| 토큰 없이 `GET /v1/me` | `401 AUTHENTICATION_FAILED` |
| USER 토큰으로 `GET /v1/me` | `200` |
| USER 토큰으로 `GET /v1/admin/ping` | `403 ACCESS_DENIED` |
| ADMIN 토큰으로 `GET /v1/admin/ping` | `200` |
| 허용 목록 밖의 경로 | `404 ENDPOINT_NOT_ALLOWLISTED` |
| 하위 서버 500 | 500 그대로 전달 |
| 하위 서버 연결 실패 | `502 DOWNSTREAM_SERVICE_UNAVAILABLE` |
| 로그인 제한 초과 | `429 LOGIN_RATE_LIMIT_EXCEEDED` (12건 중 10건 허용, 2건 차단) |

## 측정 조건

| 항목 | 값 |
| --- | --- |
| 측정일 | 2026-06-20 |
| 부하 도구 | k6 v1.7.1, 5 VUs, 1분 |
| Mock 응답 | 지연 50ms, payload 1KB |
| 반복 | 직접 호출과 Gateway 경유의 순서를 바꿔 가며 3회 |
| 경로 | 공개 `/v2/blogs`, 인증 `/v1/me`, 관리자 `/v1/admin/ping` |
| 준비 실행 | 경로마다 10회, P95 계산에서 제외 |

실제 Auth, Report, Blog, Online Judge 서버에는 부하를 보내지 않았습니다. 스크립트는 운영 대상 실행을 막고, 로컬이나 명시적으로 허용한 staging만 대상으로 합니다.

## 확인한 방법

필요 도구는 Docker, JDK 21, Go, Python 3, k6입니다.

```bash
./gradlew test
(cd monitor-bot && go test ./...)
./performance/k6/run-local.sh
```

시나리오별로도 실행할 수 있습니다(`performance/k6/direct-upstream.js`, `gateway-public-route.js`, `gateway-protected-route.js`, `gateway-error-contract.js`, `gateway-rate-limit.js`).

전후 비교는 코드 버전, k6 버전·executor, VUs·시간·실행 순서·준비 실행, 경로·Mock 지연·payload, JVM·Docker·하드웨어가 모두 같을 때만 합니다.

## 남은 한계

- 공개 GET 경로의 추가 지연만 쟀습니다. JSON 본문을 읽는 요청은 payload 1KB·64KB·1MB별 P95와 heap 사용량을 따로 재야 합니다.
- 구조화 로그를 켜고 끈 비교, Gateway 2대에서의 요청 제한 정확도는 아직 측정하지 않았습니다.
