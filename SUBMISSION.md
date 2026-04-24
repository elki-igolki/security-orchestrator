# Как сдавать это тестовое (рекомендованный формат)

Оптимально сдавать **ссылкой на репозиторий** (GitHub/GitLab) или архивом `.zip`, где есть:

- исходники
- `README.md` (запуск/проверка)
- `SECURITY_REVIEW.md` (краткий security/production-readiness аудит)
- (опционально) история коммитов

## Вариант A — репозиторий (лучший)

- Сделайте 1–3 атомарных коммита (без привязки к “до/после”):
  - `feat`: реализован ETL orchestrator
  - `chore`: docker hardening / observability (если выносите отдельно)
  - `docs`: документация
- В описании репозитория: 2–3 пункта “что сделано”.

## Вариант B — архив

Соберите `.zip` из папки проекта. Убедитесь, что внутри есть `README.md` и `SECURITY_REVIEW.md`.

## Что обычно оценивают (и что здесь закрыто)

- **Работоспособность**: `docker compose up --build`, сервисы доступны по портам, ETL создаёт тикеты
- **DevSecOps**: docker hardening (non-root, healthchecks, caps drop, resource limits), .dockerignore
- **Безопасность**: SSRF hardening (allowlist), опциональная auth на дашборд, минимизация привилегий контейнера
- **Наблюдаемость**: structured logging, Prometheus метрики (errors + latency histograms)
- **Архитектура**: разделение Extract/Transform/Load, обработка отказов через retries/timeouts, bounded in-memory state

