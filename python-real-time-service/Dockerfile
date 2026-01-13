FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Flow CSV path inside container
ENV FLOW_CSV_PATH=/shared/flows/flows.csv

# Tắt GPU cho TensorFlow trong container
ENV CUDA_VISIBLE_DEVICES=-1

# Backend service name in docker-compose
ENV BACKEND_URL=http://backend:8000

CMD ["python", "main.py"]
