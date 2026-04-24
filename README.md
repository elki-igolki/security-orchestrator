# Security Orchestrator (ETL)

Сервис-интегратор, который каждые N секунд:

- **Extract**: получает события из EDR `GET /events`
- **Transform**: проверяет уязвимость через VulnDB `POST /check`
- **Load**: при `vulnerable=true` отправляет тикет в Target `POST /ticket`

В комплекте: 3 эмулятора (EDR/VulnDB/Target) + Orchestrator с веб‑панелью и метриками Prometheus.

## Быстрый старт (Docker)

Требования:
- Docker Desktop (Linux containers / WSL2)

Запуск из корня проекта:

```powershell
docker compose up --build
```

Куда смотреть:
- **Веб‑панель**: `http://localhost:8080`
- **Метрики Prometheus**: `http://localhost:8000/metrics`
- **EDR**: `http://localhost:5001/events`
- **Health**: `http://localhost:8080/healthz`
- **Service health (auth-aware)**: `http://localhost:8080/api/health`

Остановка:

```powershell
docker compose down
```

## Переменные окружения

- `POLL_INTERVAL` (по умолчанию `30`): интервал опроса EDR в секундах
- `EDR_URL` (по умолчанию `http://localhost:5001`)
- `VULNDB_URL` (по умолчанию `http://localhost:5002`)
- `TARGET_URL` (по умолчанию `http://localhost:5003`)
- `ALLOWED_SERVICE_HOSTS` (по умолчанию `edr,vulndb,target,localhost,127.0.0.1`): allowlist хостов для исходящих HTTP (SSRF hardening)
- `DASHBOARD_AUTH_TOKEN` (по умолчанию пусто): если задан — UI и `/api/*` требуют `Authorization: Bearer <token>`

## Проверка работоспособности

EDR:

```powershell
curl http://localhost:5001/events
```

VulnDB:

```powershell
curl http://localhost:5002/check -Method POST -ContentType "application/json" -Body '{"process_name":"nginx.exe","process_version":"1.20.0"}'
```

Target (ручной тикет):

```powershell
curl http://localhost:5003/ticket -Method POST -ContentType "application/json" -Body '{"event_id":"manual","hostname":"h","process_name":"x","process_version":"0","alert_message":"m"}'
```

Оркестратор API:

```powershell
curl http://localhost:8080/api/stats
```

Если включён токен:

```powershell
curl http://localhost:8080/api/stats -H "Authorization: Bearer <token>"
```

## Наблюдаемость

Prometheus метрики: `http://localhost:8000/metrics`

Ключевые метрики:
- `orchestrator_alerts_processed_total`
- `orchestrator_tickets_created_total`
- `orchestrator_http_client_errors_total{service,method}`
- `orchestrator_http_client_request_seconds_bucket{service,method}`
- `orchestrator_poll_cycle_seconds_bucket`

## Примечания

- Если включаешь `DASHBOARD_AUTH_TOKEN`, то `curl`/браузеру для `/api/*` нужен заголовок `Authorization`.  
- `/healthz` без токена — специально для healthcheck’ов.

