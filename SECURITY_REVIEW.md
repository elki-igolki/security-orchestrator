# Security / Production Readiness Review

Контекст: orchestrator опрашивает EDR, проверяет VulnDB, создаёт тикет в Target. Эмуляторы считаются “как есть” и не меняются.

## Итог

Сфокусировано на:
- минимизации привилегий контейнера
- базовой защите панели/интеграций
- наблюдаемости по ошибкам и латентности
- устойчивости и корректном завершении процесса

## Критичные риски и исправления

### 1) Privilege hardening контейнера (CIS Docker)

**Риск**: компрометация приложения с правами root + лишние capabilities → более тяжёлые последствия.

**Исправление**:
- `Dockerfile.orchestrator`: запуск не от root
- `docker-compose.yml`: `no-new-privileges`, `cap_drop: ALL`, `read_only` + `tmpfs`, лимиты CPU/RAM/PIDs, healthcheck
- добавлен `.dockerignore`

### 2) OWASP: SSRF через конфигурацию upstream URL

**Риск**: если окружение/конфиг будет подменён, orchestrator может ходить на внутренние адреса/metadata сервисы.

**Исправление**:
- allowlist хостов `ALLOWED_SERVICE_HOSTS`
- валидация `EDR_URL/VULNDB_URL/TARGET_URL` по схеме и hostname

### 3) Broken Access Control: открытая панель/`/api/*`

**Риск**: утечка внутренней информации и упрощение разведки.

**Исправление**:
- опциональный Bearer token через `DASHBOARD_AUTH_TOKEN` (если задан — 401 без токена)

## Надёжность / отказоустойчивость

- timeouts и retries на исходящих HTTP
- метрики ошибок по каждому upstream
- graceful shutdown по SIGTERM/SIGINT
- bounded state для панели (`deque(maxlen=200)`)

## Наблюдаемость

- JSON-structured logging
- Prometheus:
  - counters: обработанные алерты, созданные тикеты, ошибки исходящих HTTP
  - histograms: длительность цикла, латентность запросов к upstream

## Что бы сделал дальше (если это production)

- вынести web в WSGI (gunicorn) и отделить poller/worker (2 процесса/контейнера)
- добавить очередь/буфер (RabbitMQ/Kafka/Redis Streams) + идемпотентность тикетов/дедуп по `event_id`
- TLS/mTLS между сервисами, секреты через Vault/KMS, RBAC и network policies
- CI: SAST (Bandit), SCA (pip-audit/OSV), container scan (Trivy), lint/format + supply-chain контроль

