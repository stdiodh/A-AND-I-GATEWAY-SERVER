# A&I Gateway Server

> Auth, Assignment & Report, Blog, Online Judge로 나뉜 A&I 백엔드의 공통 진입점입니다.

클라이언트 요청을 하나의 Gateway로 받아 공통 정책과 권한을 검사한 뒤 각 서비스로 전달합니다.

요청과 응답에는 `traceId`와 `requestId`를 남겨 서비스와 로그를 하나의 요청 단위로 추적할 수 있도록 구성했습니다.

## A&I 서비스 전체 구조

<img width="1672" height="941" alt="b37722eb-4397-4e51-8168-9162b63ee5e7" src="https://github.com/user-attachments/assets/438b56e5-4174-40d4-9a3b-dd7e66fcab7f" />

외부 요청은 Nginx와 Gateway를 거쳐 각 서비스로 전달됩니다.

과제와 채점 데이터는 서비스 간 직접 호출 대신 SNS/SQS 이벤트로 동기화합니다.

## Gateway와 운영 조회 구조

<img width="1672" height="941" alt="cc5f7d22-b57f-490c-a42f-a805aa7b4862" src="https://github.com/user-attachments/assets/290b927c-abe0-487f-9350-ff32df0232d7" />

Gateway는 다음 공통 기능을 담당합니다.

- Routing
- JWT / Role 검사
- Method · Path allowlist
- 공통 오류 응답
- `traceId` / `requestId`
- Structured Logging
- 인증 요청 Rate Limit
- Redis token context cache

Discord Monitor Bot은 Gateway JVM과 분리된 Go sidecar입니다.

CloudWatch Logs와 WEB Admin GET API를 읽기 전용으로 조회하며 서비스 데이터를 직접 변경하지 않습니다.

## 요청 처리 흐름

```mermaid
sequenceDiagram
    autonumber
    actor Client
    participant Gateway as A&I Gateway
    participant Policy as Request Policy
    participant Security as JWT / Role Check
    participant Service as Downstream Service
    participant Logs as CloudWatch Logs

    Client->>Gateway: API 요청
    Gateway->>Policy: HTTPS · Host · Method · Path · Content-Type 확인
    Policy-->>Gateway: 정책 검사 결과

    alt 요청 정책 위반
        Gateway-->>Client: 공통 오류 응답
    else 정책 통과
        Gateway->>Security: JWT와 역할 확인
        Security-->>Gateway: 인증·권한 검사 결과

        alt 인증 또는 권한 실패
            Gateway-->>Client: 401 또는 403 응답
        else 인증 성공
            Gateway->>Service: traceId · requestId와 함께 전달
            Service-->>Gateway: 서비스 응답
            Gateway->>Logs: 경로 · 상태 코드 · 지연시간 · 오류 코드 기록
            Gateway-->>Client: 공통 응답 반환
        end
    end
````

허용되지 않은 요청은 downstream까지 전달하지 않고 Gateway에서 종료합니다.

## 장애 확인 흐름

```mermaid
sequenceDiagram
    autonumber
    participant Gateway
    participant Service as Downstream Service
    participant Logs as CloudWatch Logs
    participant Bot as Discord Monitor Bot
    actor Operator as 운영자

    Gateway->>Logs: 요청·응답 구조화 로그
    Service->>Logs: 서비스 로그
    Bot->>Logs: 상태·오류·지연 요청 조회
    Logs-->>Bot: 조회 결과
    Bot-->>Operator: Discord 대시보드 또는 장애 알림

    Operator->>Bot: /ops logs 또는 trace 조회
    Bot->>Logs: traceId와 조회 조건 전달
    Logs-->>Bot: Gateway·서비스 관련 로그
    Bot-->>Operator: 확인에 필요한 결과 요약
```

운영자는 다음 명령으로 서비스 상태와 로그를 확인할 수 있습니다.

* `/ops dashboard`
* `/ops logs`
* `/ops alert`
* `/ops assignment`
* `/ops help`

![Discord Alert Example](./docs/assets/images/discord-critical-alert.png)

동일한 원인의 장애는 cooldown 동안 반복 전송하지 않으며, CRITICAL 장애만 전용 채널과 운영자 역할 mention을 사용합니다.

## k6 부하 테스트

<img width="1672" height="941" alt="71c4f0d5-75e7-49ae-a7b4-f7dd03b5af1e" src="https://github.com/user-attachments/assets/d7e9518a-844b-4022-94f5-4db06504dad4" />

동일한 Mock Downstream 환경에서 측정한 결과:

| 항목            |          결과 |
| :------------ | ----------: |
| Direct P95    | `56.959 ms` |
| Gateway P95   | `65.357 ms` |
| Gateway 추가 지연 |  `8.399 ms` |
| HTTP 실패율      |     `0.00%` |
| Check 성공률     |   `100.00%` |

해당 결과는 Gateway의 정책·라우팅·로깅 계층에 대한 **로컬 회귀 테스트 기준**이며 운영 환경의 최대 처리량을 의미하지 않습니다.

자세한 측정 조건은 [`docs/PERFORMANCE.md`](./docs/PERFORMANCE.md)에서 확인할 수 있습니다.

## 테스트

CI에서 다음 항목을 검증합니다.

```bash
./gradlew test
cd monitor-bot && go test ./...
./gradlew bootJar
```

## 실행

```bash
docker compose up -d redis gateway
curl -i http://localhost:8080/actuator/health
```

## 기술 스택

| 영역            | 기술                                                                  |
| :------------ | :------------------------------------------------------------------ |
| Gateway       | Kotlin 2.2 · Java 21 · Spring Boot 4 · Spring Cloud Gateway WebFlux |
| Security      | Spring Security · OAuth2 Resource Server · JWT                      |
| Cache         | Redis Reactive                                                      |
| Observability | Structured Logging · CloudWatch Logs                                |
| Monitor Bot   | Go 1.24 · Discord HTTP Interactions · AWS SDK                       |
| Infra         | Docker · Docker Compose · Nginx · GitHub Actions                    |
| Performance   | k6                                                                  |

## 문서

* [Gateway 오류 계약](./docs/GATEWAY_ERROR_CODES.md)
* [서비스 연동 원칙](./docs/SERVICE_GATEWAY_INTEGRATION.md)
* [성능 측정](./docs/PERFORMANCE.md)
* [Discord Monitor Bot](./monitor-bot/README.md)
