FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Đường dẫn file log Suricata bên trong CONTAINER Python
ENV EVE_PATH=/shared/logs/suricata/eve.json

# Tắt GPU cho TensorFlow trong container
ENV CUDA_VISIBLE_DEVICES=-1

# Mặc định backend chạy ở service tên "backend" port 8000
# (có thể override bằng docker-compose)
ENV BACKEND_URL=http://backend:8000

CMD ["python", "main.py"]
