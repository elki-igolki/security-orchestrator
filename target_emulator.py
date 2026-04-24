from flask import Flask, request, jsonify
import logging
import json

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@app.route('/ticket', methods=['POST'])
def create_ticket():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    # Логируем тикет (можно также записывать в файл)
    logger.info(f"Received ticket: {json.dumps(data, indent=2)}")
    return jsonify({"status": "created"}), 201

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003)