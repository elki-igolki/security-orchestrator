import os
import time
import logging
import json
import signal
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from prometheus_client import start_http_server, Counter, Histogram
from flask import Flask, render_template_string, jsonify, request, abort
import threading
from collections import deque
from urllib.parse import urlparse

# --- Flask приложение для веб-интерфейса ---
web_app = Flask(__name__)

# Хранилище последних событий (в памяти)
state_lock = threading.Lock()
last_alerts = deque(maxlen=200)
last_tickets = deque(maxlen=200)
stats = {
    "всего_алертов": 0,
    "уязвимых_найдено": 0,
    "тикетов_создано": 0,
    "последняя_проверка": "ещё не было"
}
service_health = {
    "edr": {"ok": False, "last_ok": None, "last_error": None, "last_error_time": None},
    "vulndb": {"ok": False, "last_ok": None, "last_error": None, "last_error_time": None},
    "target": {"ok": False, "last_ok": None, "last_error": None, "last_error_time": None},
}

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Orchestrator - Панель управления</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #eee;
            padding: 20px;
            min-height: 100vh;
        }
        h1 {
            text-align: center;
            margin-bottom: 30px;
            color: #00d4ff;
            text-shadow: 0 0 10px rgba(0, 212, 255, 0.3);
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 15px;
            padding: 20px;
            text-align: center;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .stat-value {
            font-size: 48px;
            font-weight: bold;
            color: #00d4ff;
        }
        .stat-label {
            font-size: 14px;
            color: #aaa;
            margin-top: 5px;
        }
        .health-row {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-bottom: 20px;
        }
        .health-card {
            background: rgba(255, 255, 255, 0.06);
            border-radius: 15px;
            padding: 16px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .health-title {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            color: #00d4ff;
            font-weight: 600;
        }
        .dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
            margin-left: 10px;
        }
        .dot-ok { background: #2ed573; box-shadow: 0 0 10px rgba(46, 213, 115, 0.4); }
        .dot-bad { background: #ff4757; box-shadow: 0 0 10px rgba(255, 71, 87, 0.4); }
        .health-meta {
            font-size: 12px;
            color: #aaa;
            line-height: 1.4;
        }
        .panel {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        .card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 20px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .card h2 {
            margin-bottom: 15px;
            color: #00d4ff;
            font-size: 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding-bottom: 10px;
        }
        .alert-item, .ticket-item {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 10px;
            border-left: 4px solid;
        }
        .alert-vulnerable { border-left-color: #ff4757; }
        .alert-safe { border-left-color: #2ed573; }
        .ticket-item { border-left-color: #ffa502; }
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            margin-right: 10px;
        }
        .badge-danger { background: #ff4757; color: white; }
        .badge-safe { background: #2ed573; color: #1a1a2e; }
        .badge-ticket { background: #ffa502; color: #1a1a2e; }
        .info-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 5px;
        }
        .label { color: #aaa; }
        .value { font-weight: 500; }
        .cve {
            background: #ff4757;
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
        }
        .update-time {
            text-align: right;
            color: #666;
            font-size: 12px;
            margin-top: 10px;
        }
        .status {
            text-align: center;
            margin-top: 20px;
            color: #2ed573;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .pulse {
            animation: pulse 2s infinite;
        }
    </style>
</head>
<body>
    <h1>🛡️ Security Orchestrator</h1>
    
    <div class="stats">
        <div class="stat-card">
            <div class="stat-value">{{ stats.всего_алертов }}</div>
            <div class="stat-label">Всего алертов получено</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{{ stats.уязвимых_найдено }}</div>
            <div class="stat-label">Обнаружено уязвимостей</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{{ stats.тикетов_создано }}</div>
            <div class="stat-label">Тикетов создано</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{{ "%.1f"|format(stats.уязвимых_найдено * 100 / stats.всего_алертов if stats.всего_алертов > 0 else 0) }}%</div>
            <div class="stat-label">Процент уязвимых</div>
        </div>
    </div>

    <div class="health-row">
        <div class="health-card">
            <div class="health-title">
                <span>EDR</span>
                <span class="dot dot-bad" id="health-dot-edr"></span>
            </div>
            <div class="health-meta" id="health-meta-edr">Загрузка…</div>
        </div>
        <div class="health-card">
            <div class="health-title">
                <span>VulnDB</span>
                <span class="dot dot-bad" id="health-dot-vulndb"></span>
            </div>
            <div class="health-meta" id="health-meta-vulndb">Загрузка…</div>
        </div>
        <div class="health-card">
            <div class="health-title">
                <span>Target</span>
                <span class="dot dot-bad" id="health-dot-target"></span>
            </div>
            <div class="health-meta" id="health-meta-target">Загрузка…</div>
        </div>
    </div>
    
    <div class="panel">
        <div class="card">
            <h2>🔍 Последние алерты</h2>
            <div id="alerts-container">
                {% for alert in alerts %}
                <div class="alert-item {% if alert.уязвим %}alert-vulnerable{% else %}alert-safe{% endif %}">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                        <span>
                            <span class="badge {% if alert.уязвим %}badge-danger{% else %}badge-safe{% endif %}">
                                {{ "⚠️ УЯЗВИМ" if alert.уязвим else "✓ БЕЗОПАСЕН" }}
                            </span>
                            <strong>{{ alert.имя_процесса }}</strong> v{{ alert.версия_процесса }}
                        </span>
                        <span class="cve">{{ alert.cve or "—" }}</span>
                    </div>
                    <div class="info-row">
                        <span class="label">Хост:</span>
                        <span class="value">{{ alert.имя_хоста }}</span>
                    </div>
                    <div class="info-row">
                        <span class="label">Сообщение:</span>
                        <span class="value">{{ alert.сообщение }}</span>
                    </div>
                    {% if alert.уязвим and alert.рекомендация %}
                    <div class="info-row">
                        <span class="label">Рекомендация:</span>
                        <span class="value">{{ alert.рекомендация }}</span>
                    </div>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
        </div>
        
        <div class="card">
            <h2>📋 Созданные тикеты</h2>
            <div id="tickets-container">
                {% for ticket in tickets %}
                <div class="ticket-item">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                        <span>
                            <span class="badge badge-ticket">🎫 ТИКЕТ</span>
                            <strong>{{ ticket.имя_процесса }}</strong> v{{ ticket.версия_процесса }}
                        </span>
                        <span class="cve">{{ ticket.cve }}</span>
                    </div>
                    <div class="info-row">
                        <span class="label">Хост:</span>
                        <span class="value">{{ ticket.имя_хоста }}</span>
                    </div>
                    <div class="info-row">
                        <span class="label">Рекомендация:</span>
                        <span class="value">{{ ticket.рекомендация }}</span>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
    </div>
    
    <div class="status">
        <span class="pulse">🟢</span> Система активна | Последняя проверка: {{ stats.последняя_проверка }}
    </div>
    <div class="update-time">
        Страница обновится автоматически через <span id="countdown">10</span> сек.
    </div>
    
    <script>
        async function refreshHealth() {
            try {
                const resp = await fetch('/api/health', { cache: 'no-store' });
                if (!resp.ok) {
                    throw new Error('health request failed: ' + resp.status);
                }
                const data = await resp.json();
                for (const svc of ['edr', 'vulndb', 'target']) {
                    const dot = document.getElementById('health-dot-' + svc);
                    const meta = document.getElementById('health-meta-' + svc);
                    const s = data.services[svc];
                    const isOk = !!s.ok;
                    dot.classList.toggle('dot-ok', isOk);
                    dot.classList.toggle('dot-bad', !isOk);

                    const lastOk = s.last_ok || '—';
                    const lastErr = s.last_error || '—';
                    const lastErrTime = s.last_error_time || '—';
                    meta.textContent = `ok: ${isOk ? 'да' : 'нет'} | last_ok: ${lastOk} | last_error: ${lastErr} | last_error_time: ${lastErrTime}`;
                }
            } catch (e) {
                // если токен включён, /api/health будет 401 — это ожидаемо, UI покажет факт недоступности
                for (const svc of ['edr', 'vulndb', 'target']) {
                    const dot = document.getElementById('health-dot-' + svc);
                    const meta = document.getElementById('health-meta-' + svc);
                    dot.classList.remove('dot-ok');
                    dot.classList.add('dot-bad');
                    meta.textContent = 'Недоступно (возможно требуется токен Authorization)';
                }
            }
        }

        let seconds = 10;
        setInterval(() => {
            seconds--;
            document.getElementById('countdown').textContent = seconds;
            if (seconds <= 0) {
                location.reload();
            }
        }, 1000);

        refreshHealth();
        setInterval(refreshHealth, 5000);
    </script>
</body>
</html>
'''

@web_app.route('/')
def index():
    _require_auth_if_configured()
    return render_template_string(
        HTML_TEMPLATE,
        stats=stats,
        alerts=list(last_alerts)[-5:][::-1],
        tickets=list(last_tickets)[-5:][::-1]
    )

@web_app.route('/api/stats')
def api_stats():
    _require_auth_if_configured()
    with state_lock:
        return jsonify(dict(stats))

@web_app.route('/api/alerts')
def api_alerts():
    _require_auth_if_configured()
    with state_lock:
        return jsonify(list(last_alerts)[-10:])

@web_app.route('/api/tickets')
def api_tickets():
    _require_auth_if_configured()
    with state_lock:
        return jsonify(list(last_tickets)[-10:])

@web_app.route('/api/health')
def api_health():
    _require_auth_if_configured()
    with state_lock:
        return jsonify({
            "status": "ok",
            "services": dict(service_health),
        })

@web_app.route('/healthz')
def healthz():
    # Без auth: используется только для liveness/readiness и docker healthcheck.
    return jsonify({"status": "ok"})

def run_web_server():
    web_app.run(host='0.0.0.0', port=8080, debug=False)

# --- Конфигурация ---
EDR_URL = os.getenv('EDR_URL', 'http://localhost:5001')
VULNDB_URL = os.getenv('VULNDB_URL', 'http://localhost:5002')
TARGET_URL = os.getenv('TARGET_URL', 'http://localhost:5003')
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL', '30'))
AUTH_TOKEN = os.getenv('DASHBOARD_AUTH_TOKEN', '').strip()
ALLOWED_SERVICE_HOSTS = {h.strip() for h in os.getenv('ALLOWED_SERVICE_HOSTS', 'edr,vulndb,target,localhost,127.0.0.1').split(',') if h.strip()}

# --- Логирование ---
logging.basicConfig(
    level=logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s"}',
    datefmt='%Y-%m-%dT%H:%M:%S%z'
)
logger = logging.getLogger("orchestrator")

# --- Метрики ---
ALERTS_PROCESSED = Counter('orchestrator_alerts_processed_total', 'Всего обработано алертов')
TICKETS_CREATED = Counter('orchestrator_tickets_created_total', 'Всего создано тикетов')
HTTP_CLIENT_ERRORS = Counter('orchestrator_http_client_errors_total', 'Ошибки исходящих HTTP', ['service', 'method'])
HTTP_CLIENT_LATENCY = Histogram('orchestrator_http_client_request_seconds', 'Латентность исходящих HTTP', ['service', 'method'])
POLL_CYCLE_SECONDS = Histogram('orchestrator_poll_cycle_seconds', 'Длительность цикла опроса')

# --- HTTP сессия ---
session = requests.Session()
retries = Retry(
    total=3,
    connect=3,
    read=3,
    backoff_factor=0.5,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=frozenset(["GET", "POST"]),
    raise_on_status=False,
)
session.mount('http://', HTTPAdapter(max_retries=retries))
session.mount('https://', HTTPAdapter(max_retries=retries))

stop_event = threading.Event()

def _require_auth_if_configured():
    if not AUTH_TOKEN:
        return
    authz = request.headers.get('Authorization', '')
    if authz != f"Bearer {AUTH_TOKEN}":
        abort(401)

def _validate_service_url(url: str, service_name: str) -> str:
    try:
        parsed = urlparse(url)
    except Exception:
        raise ValueError(f"{service_name}: invalid URL")
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"{service_name}: URL scheme must be http/https")
    if not parsed.hostname:
        raise ValueError(f"{service_name}: URL hostname missing")
    if parsed.hostname not in ALLOWED_SERVICE_HOSTS:
        raise ValueError(f"{service_name}: hostname '{parsed.hostname}' not allowed (SSRF hardening)")
    return url.rstrip("/")

EDR_URL = _validate_service_url(EDR_URL, "EDR_URL")
VULNDB_URL = _validate_service_url(VULNDB_URL, "VULNDB_URL")
TARGET_URL = _validate_service_url(TARGET_URL, "TARGET_URL")

def fetch_alerts():
    try:
        with HTTP_CLIENT_LATENCY.labels(service="edr", method="GET").time():
            response = session.get(f'{EDR_URL}/events', timeout=10)
        if response.status_code >= 400:
            HTTP_CLIENT_ERRORS.labels(service="edr", method="GET").inc()
            response.raise_for_status()
        alerts = response.json()
        with state_lock:
            service_health["edr"]["ok"] = True
            service_health["edr"]["last_ok"] = time.strftime("%H:%M:%S")
            service_health["edr"]["last_error"] = None
            service_health["edr"]["last_error_time"] = None
        logger.info(f"Получено {len(alerts)} алертов от EDR")
        ALERTS_PROCESSED.inc(len(alerts))
        with state_lock:
            stats["всего_алертов"] += len(alerts)
        return alerts
    except Exception as e:
        logger.error(f"Ошибка получения алертов: {e}")
        HTTP_CLIENT_ERRORS.labels(service="edr", method="GET").inc()
        with state_lock:
            service_health["edr"]["ok"] = False
            service_health["edr"]["last_error"] = str(e)
            service_health["edr"]["last_error_time"] = time.strftime("%H:%M:%S")
        return []

def check_vulnerability(process_name, process_version):
    try:
        with HTTP_CLIENT_LATENCY.labels(service="vulndb", method="POST").time():
            response = session.post(
                f'{VULNDB_URL}/check',
                json={'process_name': process_name, 'process_version': process_version},
                timeout=10
            )
        if response.status_code >= 400:
            HTTP_CLIENT_ERRORS.labels(service="vulndb", method="POST").inc()
            response.raise_for_status()
        data = response.json()
        with state_lock:
            service_health["vulndb"]["ok"] = True
            service_health["vulndb"]["last_ok"] = time.strftime("%H:%M:%S")
            service_health["vulndb"]["last_error"] = None
            service_health["vulndb"]["last_error_time"] = None
        return data
    except Exception as e:
        logger.error(f"Ошибка проверки уязвимости: {e}")
        HTTP_CLIENT_ERRORS.labels(service="vulndb", method="POST").inc()
        with state_lock:
            service_health["vulndb"]["ok"] = False
            service_health["vulndb"]["last_error"] = str(e)
            service_health["vulndb"]["last_error_time"] = time.strftime("%H:%M:%S")
        return {'vulnerable': False, 'уязвим': False}

def send_ticket(enriched_alert):
    try:
        with HTTP_CLIENT_LATENCY.labels(service="target", method="POST").time():
            response = session.post(f'{TARGET_URL}/ticket', json=enriched_alert, timeout=10)
        if response.status_code == 201:
            logger.info(f"Тикет создан для события {enriched_alert.get('event_id')}")
            TICKETS_CREATED.inc()
            with state_lock:
                stats["тикетов_создано"] += 1
                service_health["target"]["ok"] = True
                service_health["target"]["last_ok"] = time.strftime("%H:%M:%S")
                service_health["target"]["last_error"] = None
                service_health["target"]["last_error_time"] = None
            return True
        if response.status_code >= 400:
            HTTP_CLIENT_ERRORS.labels(service="target", method="POST").inc()
            with state_lock:
                service_health["target"]["ok"] = False
                service_health["target"]["last_error"] = f"http {response.status_code}"
                service_health["target"]["last_error_time"] = time.strftime("%H:%M:%S")
        return False
    except Exception as e:
        logger.error(f"Ошибка создания тикета: {e}")
        HTTP_CLIENT_ERRORS.labels(service="target", method="POST").inc()
        with state_lock:
            service_health["target"]["ok"] = False
            service_health["target"]["last_error"] = str(e)
            service_health["target"]["last_error_time"] = time.strftime("%H:%M:%S")
        return False

def process_alert(alert):
    process_name = alert.get('process_name')
    process_version = alert.get('process_version')
    
    if not process_name or not process_version:
        logger.warning(f"В алерте отсутствует имя или версия процесса: {alert.get('event_id')}")
        return
    
    vuln_info = check_vulnerability(process_name, process_version)
    
    # Создаём запись для отображения в интерфейсе
    alert_display = {
        "id": alert.get('event_id'),
        "имя_хоста": alert.get('hostname', 'неизвестно'),
        "имя_процесса": process_name,
        "версия_процесса": process_version,
        "сообщение": alert.get('alert_message', ''),
        "уязвим": vuln_info.get('vulnerable', False),
        "cve": vuln_info.get('critical_cve', ''),
        "рекомендация": vuln_info.get('recommendation', ''),
        "время": time.strftime("%H:%M:%S")
    }
    with state_lock:
        last_alerts.append(alert_display)
    
    if vuln_info.get('vulnerable'):
        with state_lock:
            stats["уязвимых_найдено"] += 1
        logger.info(f"Алерт {alert.get('event_id')} УЯЗВИМ, создаю тикет")
        
        enriched = {**alert, **vuln_info}
        enriched['сообщение_тикета'] = f"Обнаружена уязвимость {vuln_info.get('critical_cve')} в процессе {process_name}"
        enriched['приоритет'] = "КРИТИЧЕСКИЙ" if vuln_info.get('vulnerable') else "СРЕДНИЙ"
        
        if send_ticket(enriched):
            ticket_display = {
                "id": alert.get('event_id'),
                "имя_хоста": alert.get('hostname', 'неизвестно'),
                "имя_процесса": process_name,
                "версия_процесса": process_version,
                "cve": vuln_info.get('critical_cve', ''),
                "рекомендация": vuln_info.get('recommendation', ''),
                "время": time.strftime("%H:%M:%S")
            }
            with state_lock:
                last_tickets.append(ticket_display)
    else:
        logger.debug(f"Алерт {alert.get('event_id')} безопасен")

def run_poll_cycle():
    with POLL_CYCLE_SECONDS.time():
        start_time = time.time()
        alerts = fetch_alerts()
        for alert in alerts:
            process_alert(alert)
        duration = time.time() - start_time
        with state_lock:
            stats["последняя_проверка"] = time.strftime("%H:%M:%S")
        logger.info(f"Цикл опроса завершён за {duration:.2f} сек")

def _handle_shutdown(signum, frame):
    logger.info(f"Получен сигнал {signum}, завершаю работу...")
    stop_event.set()

def main():
    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT, _handle_shutdown)
    # Запускаем веб-сервер в отдельном потоке
    web_thread = threading.Thread(target=run_web_server, daemon=True)
    web_thread.start()
    
    # Запускаем сервер метрик Prometheus
    start_http_server(8000)
    
    logger.info("🛡️ Оркестратор запущен")
    logger.info(f"🌐 Веб-интерфейс: http://localhost:8080")
    logger.info(f"📊 Метрики: http://localhost:8000/metrics")
    logger.info(f"⏱️ Интервал опроса: {POLL_INTERVAL} сек")
    
    while not stop_event.is_set():
        try:
            run_poll_cycle()
        except Exception as e:
            logger.exception(f"Критическая ошибка в цикле: {e}")
        stop_event.wait(POLL_INTERVAL)

if __name__ == "__main__":
    main()