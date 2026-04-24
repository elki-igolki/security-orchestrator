import json
import random
from flask import Flask, jsonify

app = Flask(__name__)

SAMPLE_ALERTS = [
    {
        "id_события": "evt_123",
        "имя_хоста": "web-server-01",
        "имя_процесса": "nginx.exe",
        "версия_процесса": "1.20.0",
        "сообщение": "Подозрительный запуск процесса",
        # для совместимости с оркестратором оставляем английские ключи
        "event_id": "evt_123",
        "hostname": "web-server-01",
        "process_name": "nginx.exe",
        "process_version": "1.20.0",
        "alert_message": "Подозрительный запуск процесса"
    },
    {
        "id_события": "evt_456",
        "имя_хоста": "db-01",
        "имя_процесса": "postgres.exe",
        "версия_процесса": "13.4",
        "сообщение": "Несанкционированная попытка подключения",
        "event_id": "evt_456",
        "hostname": "db-01",
        "process_name": "postgres.exe",
        "process_version": "13.4",
        "alert_message": "Несанкционированная попытка подключения"
    },
    {
        "id_события": "evt_789",
        "имя_хоста": "app-01",
        "имя_процесса": "java.exe",
        "версия_процесса": "11.0.12",
        "сообщение": "Обнаружена инъекция в память",
        "event_id": "evt_789",
        "hostname": "app-01",
        "process_name": "java.exe",
        "process_version": "11.0.12",
        "alert_message": "Обнаружена инъекция в память"
    }
]

@app.route('/events', methods=['GET'])
def get_events():
    count = random.randint(1, 3)
    alerts = random.sample(SAMPLE_ALERTS, min(count, len(SAMPLE_ALERTS)))
    return jsonify(alerts)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)