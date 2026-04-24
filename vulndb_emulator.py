from flask import Flask, request, jsonify

app = Flask(__name__)

VULN_DB = {
    ("nginx.exe", "1.20.0"): {
        "vulnerable": True,
        "уязвим": True,
        "critical_cve": "CVE-2026-12345",
        "критическая_cve": "CVE-2026-12345",
        "recommendation": "Обновить до версии 1.21.0 или выше",
        "рекомендация": "Обновить до версии 1.21.0 или выше",
        "описание": "Уязвимость позволяет удалённо выполнить код"
    },
    ("postgres.exe", "13.4"): {
        "vulnerable": True,
        "уязвим": True,
        "critical_cve": "CVE-2026-67890",
        "критическая_cve": "CVE-2026-67890",
        "recommendation": "Обновить до версии 14.1 или выше",
        "рекомендация": "Обновить до версии 14.1 или выше",
        "описание": "Уязвимость повышения привилегий"
    }
}

@app.route('/check', methods=['POST'])
def check_vulnerability():
    data = request.get_json()
    if not data:
        return jsonify({"ошибка": "Неверный JSON"}), 400

    process_name = data.get('process_name')
    process_version = data.get('process_version')
    
    key = (process_name, process_version)
    result = VULN_DB.get(key, {
        "vulnerable": False,
        "уязвим": False,
        "critical_cve": None,
        "критическая_cve": None,
        "recommendation": None,
        "рекомендация": None,
        "описание": "Уязвимостей не найдено"
    })
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002)