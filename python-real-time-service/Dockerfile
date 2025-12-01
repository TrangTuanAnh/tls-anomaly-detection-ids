FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# EVE_PATH đã set mặc định trong config.py là /shared/logs/suricata/eve.json
ENV EVE_PATH=/shared/logs/suricata/eve.json

CMD ["python", "main.py"]
